import string
from typing import Annotated

from pydantic import field_validator


def validate_strong_password(v: str) -> str:
    """
    Validates that a password meets strong security requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not v:
        raise ValueError("Password is required")

    special_chars = set(string.punctuation)

    errors = []

    if len(v) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in v):
        errors.append("one uppercase letter")
    if not any(c.islower() for c in v):
        errors.append("one lowercase letter")
    if not any(c.isdigit() for c in v):
        errors.append("one digit")
    if not any(c in special_chars for c in v):
        errors.append("one special character")

    if errors:
        raise ValueError(
            f"Password must contain {', '.join(errors[:-1]).replace(', ', ', and ')}"
            if len(errors) > 1
            else f"Password must have {errors[0]}"
        )

    return v

StrongPassword = Annotated[str, field_validator("password")(validate_strong_password)]