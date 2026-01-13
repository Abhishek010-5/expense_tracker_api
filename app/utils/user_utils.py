from app.database import get_db

import logging
from werkzeug.datastructures import FileStorage
from typing import Tuple,Optional, Dict
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

def get_profile_picture_by_email(email: str,) -> Optional[Dict]:
    try:
        
        db = get_db()
        collection = db["profile_pictures"]
        doc = collection.find_one({"_id": email.strip()})
        if not doc:
            return None

        return {
            "data": doc["data"],
            "content_type": doc["content_type"],
            "filename": doc.get("filename", "profile.jpg"),
            "size_bytes": doc.get("size_bytes"),
            "uploaded_at": doc.get("uploaded_at")
        }

    except Exception as e:
        raise Exception(f"Failed to get profile picture: {str(e)}")
    


def save_profile_picture(file: FileStorage, email: str) -> bool:
    """
    Saves or updates profile picture with proper validation.
    Returns True if operation succeeded.
    Raises ValueError for client/input errors
    Raises RuntimeError for server-side problems
    """
    # ── Basic file existence checks ───────────────────────────────
    if not file:
        raise ValueError("No file received")

    if not file.filename or file.filename.strip() == '':
        raise ValueError("No filename provided - file appears empty")

    # ── Size validation (very important!) ─────────────────────────
    MAX_ALLOWED_SIZE = 5 * 1024 * 1024  # 5 MB

    # Get size without loading whole file into memory twice
    file.seek(0, 2)           # move to end
    file_size = file.tell()
    file.seek(0)              # back to beginning

    if file_size == 0:
        raise ValueError("Uploaded file is empty")

    if file_size > MAX_ALLOWED_SIZE:
        raise ValueError(
            f"File too large. Maximum allowed size is {MAX_ALLOWED_SIZE // 1024 // 1024}MB"
        )

    # ── Content-Type / MIME validation ────────────────────────────
    allowed_mimetypes = {
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/webp',
        'image/gif'
    }

    if not file.content_type:
        raise ValueError("Cannot determine file content type")

    if file.content_type not in allowed_mimetypes:
        raise ValueError(
            f"Invalid image format. Allowed types: JPEG, PNG, WebP, GIF"
        )

    # ── Very basic filename extension sanity check ────────────────
    # (this is secondary — content-type is more important)
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if f".{ext}" not in allowed_extensions:
        raise ValueError("File extension not allowed")

    # ── Actual processing ─────────────────────────────────────────
    try:
        image_bytes = file.read()  # now safe to read

        # Double-check (defensive)
        if len(image_bytes) != file_size:
            raise RuntimeError("File size changed during read operation")

        db = get_db()
        collection = db["profile_pictures"]

        result = collection.update_one(
            {"_id": email},
            {
                "$set": {
                    "data": image_bytes,
                    "content_type": file.content_type,
                    "size_bytes": file_size,
                    "filename": file.filename,
                    "uploaded_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            },
            upsert=True
        )

        return result.matched_count == 1 or result.upserted_id is not None

    except ValueError:
        raise  # re-raise client validation errors

    except Exception as e:
        # In real project → log full stack trace here
        raise RuntimeError(f"Failed to save profile picture: {str(e)}")
    
def delete_user_profile_picture(email:str)->bool:
    email = email.strip()
    db = get_db()
    collection = db["profile_pictures"]
    
    response = collection.delete_one({"_id":email}).deleted_count
    
    return True if response == 1 else False
    