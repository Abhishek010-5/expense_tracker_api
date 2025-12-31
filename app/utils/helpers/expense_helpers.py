# utils/expense_helpers.py

from datetime import datetime, timedelta

from app.database import get_db  


def _get_transaction_count(email: str, start_date: datetime, end_date: datetime) -> int:
    """Internal: Count transactions in a date range."""
    pipeline = [
        {"$match": {"email": email, "date": {"$gte": start_date, "$lt": end_date}}},
        {"$count": "amount"}
    ]
    db = get_db()
    collection = db['expense']
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