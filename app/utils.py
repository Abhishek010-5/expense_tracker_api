import re
import string

import random
import smtplib
from datetime import datetime
from email.message import EmailMessage
from typing import List, Dict, Any, Optional, Tuple

from app.redisdb import connect_to_redis
from app.database import get_db
from app.config import settings

import redis
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask import request
from pydantic import field_validator, ValidationError, ValidationInfo

logger = logging.getLogger(__name__)

# Function for hasing


def encrypt_password(password: str) -> Optional[str]:
    """
    Securely hash a password using PBKDF2 with HMAC-SHA256 (default and recommended).

    Args:
        password (str): Plain text password (guaranteed to be non-empty str by route validation).

    Returns:
        str | None: Hashed password on success, None if hashing fails (error logged).

    Note:
        Any errors during hashing are logged but not raised — caller should check for None.
    """
    try:
        hashed = generate_password_hash(password)
        return hashed

    except ValueError as e:
        # This can happen if somehow an invalid method is passed (unlikely with default usage)
        logger.error("ValueError during password hashing: %s", e)
        return None

    except Exception as e:
        # Catch-all for unexpected issues (e.g., crypto backend problems)
        logger.exception("Unexpected error while hashing password: %s", e)
        return None

def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a plain text password against a stored hash.

    Args:
        stored_hash (str): Hashed password from the database (from encrypt_password())
        password (str): Plain text password provided by the user

    Returns:
        bool: True if the password matches the hash, False otherwise
              (including if an error occurs during verification)

    Note:
        - Errors during verification are logged but not raised.
        - Invalid or malformed hashes are treated as mismatches (secure default).
    """
    if not stored_hash or not password:
        logger.warning("Empty stored_hash or password provided to verify_password")
        return False

    try:
        return check_password_hash(stored_hash, password)

    except Exception as e:
        logger.error("Error verifying password hash: %s", e)
        return False


# Utility function for OTP


def generate_otp(length: int = 6) -> str:
    """
    Generate a random numeric OTP of specified length.
    """
    if length <= 0:
        logger.error("Invalid OTP length requested: %s", length)
        raise ValueError("OTP length must be positive")
    return "".join(random.choices(string.digits, k=length))

def send_otp_to_user(to_email: str, otp: str) -> bool:
    """
    Send a 6-digit OTP via email using Gmail SMTP.

    Args:
        to_email (str): Recipient email address
        otp (str): The OTP to send

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not settings.mail or not settings.mail_password:
        logger.error("Email credentials not configured in settings")
        return False

    sender = settings.mail
    password = settings.mail_password

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = "Your verification code"
    msg.set_content(
        f"Your verification code is {otp}\n\n"
        "It expires in 5 minutes.\n"
        "Do not share this code with anyone."
    )

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("Failed to authenticate with Gmail SMTP (invalid credentials)")
        return False
    except smtplib.SMTPRecipientsRefused:
        logger.error("Recipient email rejected: %s", to_email)
        return False
    except smtplib.SMTPServerDisconnected:
        logger.error("SMTP server disconnected unexpectedly")
        return False
    except Exception as e:
        logger.exception("Unexpected error sending OTP email to %s: %s", to_email, e)
        return False

def sendOtp(email: str, expiry_seconds: int = 300) -> bool:
    """
    Generate OTP, store in Redis with expiry, and send via email.

    Args:
        email (str): User's email
        expiry_seconds (int): OTP validity duration

    Returns:
        bool: True if OTP generated, stored, and sent successfully
    """
    try:
        otp = generate_otp()
        key = f"otp:{email}"

        redis_client = connect_to_redis()
        redis_client.set(key, otp, ex=expiry_seconds)

        success = send_otp_to_user(email, otp)
        if success:
            return True
        else:
            # Clean up Redis if email failed
            try:
                redis_client.delete(key)
            except:
                pass
            logger.warning("OTP stored but email failed to send for %s", email)
            return False

    except redis.RedisError as e:
        logger.error("Redis error while storing OTP for %s: %s", email, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error in sendOtp for %s: %s", email, e)
        return False

def verify_user_otp(email: str, entered_otp: str) -> bool:
    """
    Verify entered OTP against stored value in Redis.
    Deletes OTP on success (one-time use) or if invalid/expired.

    Returns:
        bool: True only if OTP matches and is valid
    """
    try:
        redis_client = connect_to_redis()
        key = f"otp:{email}"
        stored_otp_bytes = redis_client.get(key)

        if stored_otp_bytes is None:
            logger.info("OTP verification failed: expired or not found for %s", email)
            return False

        stored_otp = stored_otp_bytes.decode('utf-8') if isinstance(stored_otp_bytes, bytes) else stored_otp_bytes

        if stored_otp == entered_otp.strip():
            redis_client.delete(key)
            return True
        else:
            logger.info("Invalid OTP entered for %s", email)
            # Optional: delete on too many failures? Rate limit elsewhere.
            return False

    except redis.RedisError as e:
        logger.error("Redis error during OTP verification for %s: %s", email, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error verifying OTP for %s: %s", email, e)
        return False
    finally:
        # Optional: always clean up on verification attempt?
        # Not recommended — allows replay if not deleted on success
        pass

# Function for user relate operations

def update_password(email: str, new_password: str) -> bool:
    """
    Updates the user's password in the database.

    Args:
        email (str): The user's email (used as _id in the users collection).
        new_password (str): The new plain-text password to set.

    Returns:
        bool: True if exactly one document was modified, False otherwise.

    Raises:
        Logs any exceptions that occur during the update process.
    """
    try:
        db = get_db()
        collection = db["users"]
    
        hashed_new_password = encrypt_password(new_password)
        
        result = collection.update_one(
            {"_id": email},
            {"$set": {"password": hashed_new_password}}
        )

        if result.modified_count == 1:
            return True
        else:
            logger.warning("No user found or password unchanged for email: %s (modified_count: %d)", 
                           email, result.modified_count)
            return False

    except Exception as e:
        logger.error("Failed to update password for email: %s | Error: %s", email, str(e), exc_info=True)
        return False


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
            "created_at": datetime.now(),
        }
    ).acknowledged

    return res


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
        user_data = collection.find_one({"_id": email},{"username":1,"password":1})
    except Exception as e:
        logger.error("Exception: ", e)
        return None
    return user_data


def verify_user(email: str, password: str) -> Tuple[bool, str]:

    user = get_user(email)

    if not user or user == {}:
        return False
    system_password = user.get("password")
    username = user.get("username")
    email = user.get("_id")
    return (verify_password(system_password, password),username, email)


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