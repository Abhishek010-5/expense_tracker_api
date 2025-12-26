from typing import Optional
from werkzeug.security import generate_password_hash,check_password_hash
import logging

logger = logging.getLogger(__name__)

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