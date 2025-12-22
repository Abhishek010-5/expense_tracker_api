import string
from typing import Annotated

from pydantic.functional_validators import AfterValidator


def validate_strong_password(v: str) -> str:
    """
    Validates that a password meets strong security requirements.
    Raises ValueError with a clear message if any check fails.
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
        if len(errors) == 1:
            message = f"Password must have {errors[0]}"
        elif len(errors) == 2:
            message = f"Password must have {errors[0]} and {errors[1]}"
        else:
            message = f"Password must contain: {', '.join(errors[:-1])}, and {errors[-1]}"
        raise ValueError(message)

    return v


# Reusable strong password type — now works reliably everywhere!
StrongPassword = Annotated[str, AfterValidator(validate_strong_password)]