import string
from typing import Annotated
from pydantic.functional_validators import AfterValidator
from pydantic_core import PydanticCustomError


def _strong_password_validator(v: str) -> str:
    """
    Validates that the password contains:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character from string.punctuation
    """
    if not any(c.isupper() for c in v):
        raise PydanticCustomError(
            "uppercase_missing",
            "Password must contain at least one uppercase letter",
        )

    if not any(c.islower() for c in v):
        raise PydanticCustomError(
            "lowercase_missing",
            "Password must contain at least one lowercase letter",
        )

    if not any(c.isdigit() for c in v):
        raise PydanticCustomError(
            "digit_missing",
            "Password must contain at least one digit",
        )

    if not any(c in string.punctuation for c in v):
        raise PydanticCustomError(
            "special_missing",
            "Password must contain at least one special character (!@#$%^&* etc.)",
        )

    return v

StrongPassword = Annotated[str, AfterValidator(_strong_password_validator)]