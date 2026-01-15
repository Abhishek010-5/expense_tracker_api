from typing import Dict,Any,List,Optional
from app.database import get_db
import logging
from datetime import datetime, timedelta, timezone

from app.utils.helpers.expense_helpers import (  
    get_user_weekly_transactions,
    get_user_monthly_transactions,
    get_user_yearly_transactions,
    get_daily_expense
)

logger = logging.getLogger(__name__)

def add_user_expense(expense_details: Dict[str, Any]) -> bool:
    """
    Add a new expense record to the database.

    Args:
        expense_details (Dict[str, Any]): Dictionary containing the expense data.
                                         Expected to include fields like 'email', 'amount',
                                         'category', 'date', etc.

    Returns:
        bool: True if the insert operation was acknowledged by the server,
              False otherwise (very rare in normal operation).

    Raises:
        RuntimeError: If a database error occurs during connection or insertion
                      (e.g., connection failure, write concern error, validation error).
    """
    try:
        db = get_db()
        collection = db["expense"]

        # Perform the insertion
        result = collection.insert_one(expense_details)

        # Return the acknowledged status (usually True if no exception was raised)
        return bool(result.acknowledged)

    except Exception as e:
        user_email = expense_details.get("email", "unknown")
        logging.error(f"Failed to add expense for user {user_email}: {str(e)}")
        raise RuntimeError("Failed to save expense to database") from e

def get_user_expense(email: str) -> List[Dict]:
    """
    Retrieve all expenses for a user identified by their email address from the database.

    Args:
        email (str): The email address of the user to fetch expenses for.

    Returns:
        List[Dict]: A list of expense documents (each as a dictionary) belonging to the user.
                    Returns an empty list if no expenses are found.

    Raises:
        RuntimeError: If there is an error connecting to the database or executing the query.
    """
    try:
        db = get_db()
        collection = db["expense"]
        
        curr_date = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
        next_day = curr_date + timedelta(days=1)
        
        expenses = list(collection.find(
            {"email": email, "date": {"$gte": curr_date, "$lt": next_day}},
            {"_id": 0, "email": 0}
        ))

        return expenses  # Returns [] if no documents found, which is clean and expected

    except Exception as e:
        logging.error(f"Failed to retrieve expenses for user {email}: {str(e)}")
        raise RuntimeError(
            f"Database error while fetching expenses for user '{email}'"
        ) from e

def get_user_curr_year_expense(email: str) -> int:
    db = get_db()
    collection = db["expense"]

    today = datetime.today()
    start_of_year = datetime(today.year, 1, 1)
    end_of_year = datetime(today.year + 1, 1, 1)

    total_expense = list(
        collection.aggregate(
            [
                {
                    "$match": {
                        "email": email,
                        "date": {"$gte": start_of_year, "$lt": end_of_year},
                    }
                },
                {
                    "$group": {
                        "_id": None,  # or null
                        "total_amount": {"$sum": "$amount"},
                    }
                },
            ]
        )
    )

    return total_expense

def get_user_expenses_by_date_range(email: str, startDate: datetime, endDate: datetime) -> List[Dict]:
    db = get_db()
    collection = db["expense"]


    query = {"email": email,"date": {"$gte": startDate,"$lte": endDate}}

    expenses = list(collection.find(query,{"_id":0,"email":0}))

    return expenses

def get_user_curr_week_expense(email: str) -> List[Dict]:
    """
    Retrieve daily expense totals for the current week (Monday to Sunday) for a given user.
    ...
    Raises:
        pymongo.errors.PyMongoError: If database connection or query fails.
    """
    today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    monday = today - timedelta(days=today.weekday())
    next_monday = monday + timedelta(days=7)

    db = get_db()
    collection = db["expense"]

    pipeline = [
        {"$match": {"email": email, "date": {"$gte": monday, "$lt": next_monday}}},
        {"$group": {"_id": {"$dateTrunc": {"date": "$date", "unit": "day"}}, "dailyTotal": {"$sum": "$amount"}}},
        {"$sort": {"_id": 1}}
    ]

    return list(collection.aggregate(pipeline))

def get_user_monthly_avg_expense(email: str, month: int | None = None, year: int | None = None) -> float:
    """
    Get average expense for a specific month/year.
    If month/year not provided → uses current month/year.
    Returns 0.0 if no expenses in that month.
    """
    now = datetime.now()
    
    # Default to current month/year if not provided
    target_year = year or now.year
    target_month = month or now.month
    
    # Start of the month: day 1, time 00:00:00
    start_of_month = datetime(target_year, target_month, 1)
    
    # Calculate end of the month:
    # Go to day 1 of next month, then subtract 1 microsecond
    if target_month == 12:
        end_of_month = datetime(target_year + 1, 1, 1) - timedelta(microseconds=1)
    else:
        end_of_month = datetime(target_year, target_month + 1, 1) - timedelta(microseconds=1)
    
    pipeline = [
        {
            "$match": {
                "email": email,
                "date": {"$gte": start_of_month, "$lte": end_of_month}
            }
        },
        {
            "$group": {
                "_id": None,
                "monthlyAvgExpense": {"$avg": "$amount"}
            }
        }
    ]
    db = get_db()
    collection = db['expense']
    result = next(collection.aggregate(pipeline), None)
    
    return result["monthlyAvgExpense"] if result else 0.0

def get_user_transaction_summary(
    email: str,
    day: Optional[int] = None,
    month: Optional[int] = None,
    year: Optional[int] = None
) -> dict:
    """
    Accepts separate weekly, month, year as integers.
    Builds target date intelligently.
    """
    now_utc = datetime.now(timezone.utc)
    current_day = now_utc.day
    current_month = now_utc.month
    current_year = now_utc.year  

    # Determine target date
    target_year = year or current_year
    target_month = month or current_month
    target_day = day or current_day

    # If any date part is provided, ensure year is set
    if day is not None or month is not None:
        if year is None:
            target_year = current_year  # default to current year if partial date
        # else: 
            # raise ValueError("year is required when day or month is provided")

    # Create timezone-aware datetime
    try:
        target_date = datetime(target_year, target_month, target_day, tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(f"Invalid date: {target_day}/{target_month}/{target_year} — {str(e)}")

    # Yearly override: if year provided alone, use current day/month but that year for yearly count
    yearly_target = year or target_date.year

    return {
        "email": email,
        "day": target_date.day,
        "month": target_date.month,
        "year": target_date.year,
        "weekly_transactions": get_user_weekly_transactions(email, target_date),
        "monthly_transactions": get_user_monthly_transactions(email, target_date),
        "yearly_transactions": get_user_yearly_transactions(email, yearly_target),
    }
    
def get_curr_month_daily_expense(email:str)->list[dict]:
    expense_details = get_daily_expense(email)
    return {"expense":expense_details}

def get_expense_payment_method_and_total(email:str)->list[dict]:
    db = get_db()
    collection = db["expense"]
    year = datetime.now().year
    curr_year_starts = datetime(year, 1, 1)
    next_year_starts = datetime(year + 1, 1,1)
    
    pipeline = [
        {"$match":{"email":email,"date":{"$gte":curr_year_starts,"$lt":next_year_starts}}},
        {"$group":{"_id":"$payment_method","amountSpent":{"$sum":"$amount"}}}
    ]
    
    expense_details = list(collection.aggregate(pipeline))
    return {"expense_details":expense_details}

def get_amount_and_category_wise_spended_amount(email:str)->List[Dict]:
    db = get_db()
    collection = db["expense"]
    
    pipeline = [
    {"$match": {"email":email}},
    {"$group": {
        "_id": "$category",
        "totalSpent": {"$sum": "$amount"}
    }},
    {"$sort": {"totalSpent": -1}},
    {"$project": {
        "category": "$_id",
        "totalSpent": 1,
        "_id": 0
    }}
    ]
    
    expense_summary = list(collection.aggregate(pipeline=pipeline))
    
    return expense_summary
