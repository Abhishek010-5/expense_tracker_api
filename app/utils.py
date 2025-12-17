import re
import string

import random
import smtplib
from datetime import datetime
from email.message import EmailMessage

from typing import List, Dict, Any
from app.redisdb import connect_to_redis
from app.database import get_db

import redis
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from app.config import settings
from flask import request


# Function for hasing


def encrypt_password(password: str) -> str:
    """
    Securely hash a password using PBKDF2 with HMAC-SHA256 (default and recommended).

    Args:
        password (str): Plain text password

    Returns:
        str: Hashed password (as string)
    """
    return generate_password_hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a password against a stored hash.

    Args:
        stored_hash (str): Previously generated hash from encrypt_password()
        password (str): Plain text password to verify

    Returns:
        bool: True if password matches, False otherwise
    """
    return check_password_hash(stored_hash, password)


# Function to valid username, email and password


def validate_username(username: str) -> bool:
    """Basic username validation: alphanumeric + underscore, 3-20 chars"""
    return bool(username and re.match(r"^[a-zA-Z0-9_]{3,20}$", username))


def validate_password(v: str) -> bool:
    # Check for 8+ chars, uppercase, lowercase, digit, and special character
    special_chars = set(string.punctuation)
    if (
        len(v) < 8
        or not any(c.isupper() for c in v)
        or not any(c.islower() for c in v)
        or not any(c.isdigit() for c in v)
        or not any(c in special_chars for c in v)
    ):
        return False
    return True


def validate_email(email: str) -> bool:
    patter = r"^\w+@\w+\.\w+$"
    if re.match(patter, email):
        return True
    return False


# Utility function for OTP


def generate_otp(length: int = 6) -> str:
    return "".join(random.choices(string.digits, k=length))


def send_otp_to_user(to_email: str, otp: str = None) -> str:
    """
    Send a 6-digit OTP to the given email (plain text, minimal & clean).

    Args:
        to_email (str): Recipient's email
        otp (str, optional): Custom OTP. If None, generates a random one.

    Returns:
        str: The OTP that was sent
    """

    sender = settings.mail 
    password = settings.mail_password  

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = "Your verification code"
    msg.set_content(f"Your verification code is {otp}\n\nIt expires in 5 minutes.")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.send_message(msg)
    return True


def sendOtp(email: str, expiry_seconds: int = 300) -> bool:
    """
    Generate and store OTP in Redis with expiry
    Returns the OTP (for testing or logging – never send in prod logs!)
    """
    try:
        otp = generate_otp()
        key = f"otp:{email}"
        redis_client = connect_to_redis()
        redis_client.set(key, expiry_seconds, otp)
        send_otp_to_user(email, otp)
    except redis.RedisError as e:
            print(f"Redis error for {email}: {e}")
            return False
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return False
    return True


def verify_user_otp(email: str, entered_otp: str) -> bool:
    """
    Verify OTP and delete it immediately on success (one-time use)
    """
    redis_client = connect_to_redis()
    key = f"otp:{email}"
    stored_otp = redis_client.get(key)

    if stored_otp is None:
        print(f"[FAILED] OTP expired or not found for {email}")
        return False

    if stored_otp == entered_otp.strip():
        redis_client.delete(key)  # One-time use
        print(f"[SUCCESS] OTP verified for {email}")
        return True
    else:
        print(f"[FAILED] Invalid OTP for {email}")
        print(stored_otp)
        return False


# Function for user relate operations


def update_password(email: str, new_password) -> bool:
    """
    Updates the user password

    Args:
        username(str): username to update the user password
        new_password(str): new password which the use want to update
    returns:
        bool: if the modified count is 1 returns true else false
    """
    db = get_db()
    collection = db["users"]
    hashed_new_password = encrypt_password(new_password)
    modifiedCount = collection.update_one(
        {"_id": email}, {"$set": {"password": hashed_new_password}}
    ).modified_count

    return modifiedCount == 1


def create_user(email: str, username: str, password: str) -> bool:
    """
    Add a new user to the MongoDB 'users' collection with a securely hashed password.

    This function creates a new user document with the provided email (used as the primary key),
    username, and hashed password. The account is initially marked as unverified.

    Args:
        email (str): User's email address. This will be used as the unique document _id.
        username (str): Desired username for the user.
        password (str): Plain-text password provided by the user.

    Returns:
        bool: True if the user was successfully inserted into the database,
              False otherwise (e.g., duplicate email or insertion failure).

    Raises:
        DuplicateKeyError: If a user with the same email already exists (MongoDB will raise this).
        Any database connection or operation errors from PyMongo.

    Example:
        >>> success = add_user("user@example.com", "john_doe", "SecurePass123!")
        >>> if success:
        ...     print("User registered successfully")
    """
    db = get_db()
    hash_password = encrypt_password(password)
    collection = db["users"]

    res = collection.insert_one(
        {
            "_id": email,
            "username": username,
            "password": hash_password,
            "is_mail_verified": False,
            "created_at": datetime.now(),  # Fixed: use datetime.now(), not datetime.today().now()
        }
    ).acknowledged

    return res


def verify_user_mail(email: str) -> bool:
    """
    This verify user mail after verifyigng the otp in the db so the users can login into the account

    Args:
        email(str): Email is by the verify email route to verify the email
    Return:
        bool: true if the status of the mail is updated else false
    """
    db = get_db()
    collection = db["users"]
    modified_count = collection.update_one(
        {"_id": email}, {"$set": {"is_mail_verified": True}}
    ).modified_count
    return modified_count == 1


def user_exists(email: str) -> bool:
    """
    Check if a user with the given email exists in the database.

    This function queries the 'users' collection to determine whether a document
    with the provided email as its `_id` exists.

    Args:
        email (str): The email address of the user to validate.
                     Must be a non-empty string.

    Returns:
        bool: True if a user with the given email exists in the database,
              False otherwise.
    """
    db = get_db()
    collection = db["users"]
    res = collection.find_one({"_id": email}, {"_id": 1})
    if not res:
        return False
    return True


def get_user(email: str) -> dict:
    """
    Get users details from the data

    Args:
        email(str): email provide by the user at the time of signin
    Returns:
        dict: A dict contain email, username and password
    """
    try:
        db = get_db()
        collection = db["users"]
        user_data = collection.find_one({"_id": email})
    except Exception as e:
        print("Exception: ", e)
        return None
    return user_data


def verify_user(email: str, password: str) -> bool:

    user = get_user(email)

    if not user or user == {}:
        return False
    system_password = user.get("password")

    return verify_password(system_password, password)


# Expense related utility functions


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

        # Find all expenses for the given email, excluding _id and email fields from output
        expenses = list(collection.find({"email": email}, {"_id": 0, "email": 0}))

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


def get_username_for_rate_limit():
    username = request.form.get("username") or request.form.get("email") or "unknown"
    return f"user:{username.lower().strip()}"