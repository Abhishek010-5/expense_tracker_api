from pydantic import EmailStr, Field, SecretStr, BaseModel, field_validator
from typing import Annotated

from app.validators import StrongPassword

Username = Annotated[
    str,
    Field(
        min_length=3,
        max_length=30,
        description="Username must be between 3 and 30 characters",
    ),
]

Day = Annotated[int, Field(None, ge=1, le=31, description="Day of month (1-31)")]
Month = Annotated[int, Field(None,ge=1,le=12, description="Month (1-12)")]
Year = Annotated[int, Field(None, ge=2025, le=2030,description="Year (2000-2100). Required if day or month is provided.",)]


class UserCredential(BaseModel):
    email: EmailStr
    password: SecretStr


class UserCreate(BaseModel):
    username: Username
    email: EmailStr
    password: StrongPassword

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()


class UpdatePassword(BaseModel):
    new_password: StrongPassword
    old_password: SecretStr


class ForgotPassword(BaseModel):
    email: EmailStr
    new_password: StrongPassword


class SendOTP(BaseModel):
    email: EmailStr
    
class VerifyOTP(BaseModel):
    email: EmailStr
    otp: Annotated[str, Field(min_length=6, max_length=6)]