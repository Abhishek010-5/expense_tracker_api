# utils/expense_helpers.py

from datetime import datetime, timedelta
from typing import List, Dict

from app.database import get_db


def _get_transaction_count(email: str, start_date: datetime, end_date: datetime) -> int:
    """Internal: Count transactions in a date range."""
    pipeline = [
        {"$match": {"email": email, "date": {"$gte": start_date, "$lt": end_date}}},
        {"$count": "amount"},
    ]
    db = get_db()
    collection = db["expense"]
    result = next(collection.aggregate(pipeline), None)
    return result["amount"] if result else 0


def get_next_month_start(target_date: datetime) -> datetime:
    """Internal: Get first day of next month."""
    year, month = target_date.year, target_date.month
    if month == 12:
        return datetime(year + 1, 1, 1)
    return datetime(year, month + 1, 1)


def get_user_weekly_transactions(email: str, target_date: datetime) -> int:
    start = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=7)
    return _get_transaction_count(email, start, end)


def get_user_monthly_transactions(email: str, target_date: datetime) -> int:
    start = target_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = get_next_month_start(start)
    return _get_transaction_count(email, start, end)


def get_user_yearly_transactions(email: str, year: int) -> int:
    start = datetime(year, 1, 1)
    end = datetime(year + 1, 1, 1)
    return _get_transaction_count(email, start, end)


def fill_missing_days_with_zero(
    partial_data: List[Dict],
    start_date: datetime,
    end_date: datetime
) -> List[Dict]:
    """
    Takes a list of daily expense records (which may miss some days)
    and returns a complete list with every day between start_date and end_date,
    filling missing days with dailyTotal = 0.

    Args:
        partial_data: List of dicts like [{"date": datetime, "dailyTotal": float}, ...]
        start_date: First day of the range (inclusive)
        end_date: Day after the last day (exclusive)

    Returns:
        List of dicts, one for each day in the range, with missing days set to 0
    """
    # Create a lookup dictionary: date → dailyTotal
    found = {}
    for entry in partial_data:
        # Normalize to date only (in case time part is present)
        day = entry["date"].date()
        found[day] = entry["dailyTotal"]

    # Generate all days and build result
    result = []
    current = start_date
    while current < end_date:
        day_date = current.date()
        result.append({
            "date": current,  # keeping full datetime; change to current.date() if you prefer date objects
            "dailyTotal": found.get(day_date, 0.0)
        })
        current += timedelta(days=1)

    return result


def get_curr_month() -> datetime:
    now = datetime.now()
    curr_month = datetime(now.year, now.month, 1)
    return curr_month


def get_daily_expense(email: str) -> List[Dict]:
    curr_month = get_curr_month()
    next_month = get_next_month_start(curr_month)

    pipeline = [
        {"$match": {
            "email": email,
            "date": {"$gte": curr_month, "$lt": next_month}
        }},
        {
            "$group": {
                "_id": {"$dateTrunc": {"date": "$date", "unit": "day"}},
                "dailyTotal": {"$sum": "$amount"},
            }
        },
        {"$sort": {"_id": 1}},
    
        {"$project": {
            "date": "$_id",
            "dailyTotal": 1,
            "_id": 0
        }}
    ]
    db = get_db()
    collection = db["expense"]
    result = list(collection.aggregate(pipeline))
    expense_details = fill_missing_days_with_zero(result, curr_month, next_month)
    return expense_details
