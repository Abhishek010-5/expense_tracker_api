from app.database import get_db

import logging
from typing import Tuple,Optional
from datetime import datetime
from .password_utils import encrypt_password, verify_password

logger = logging.getLogger(__name__)

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

def verify_user(email: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
    user = get_user(email)
    if not user or user == {}:
        return False, None, None  
    
    system_password = user.get("password")
    if system_password is None:
        return False, None, None
    
    username = user.get("username")
    verified_email = user.get("_id")  
    
    is_valid = verify_password(system_password, password)
    return is_valid, username, verified_email

def get_user_profile(email:str)->Optional[str | None ]:
    db = get_db()
    collection = db["users"]
    res = collection.find_one({"_id":email},{"_id":0,"username":1})
    username = res.get("username")
    
    if not username:
        return None
    return username

def delete_user_and_expense(email: str) -> bool:
    db = get_db()
    
    user_res = db["users"].delete_one({"_id": email})
    if user_res.deleted_count == 0:
        return False
        
    expense_res = db["expense"].delete_many({"email": email})
    
    return expense_res.deleted_count > 0   