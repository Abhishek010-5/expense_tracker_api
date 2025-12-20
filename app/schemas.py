from pydantic import BaseModel, EmailStr, Field, SecretStr
from typing import Annotated
from validators import StrongPassword  

Username = Annotated[
    str,
    Field(
        min_length=3,
        max_length=30,
        description="Username must be between 3 and 30 characters",
    ),
]

SecurePassword = Annotated[
    StrongPassword,  # Inherits all strong password rules
    Field(
        min_length=8,
        max_length=256,
        description="Password must be 8-256 chars and include uppercase, lowercase, digit, and special char",
    ),
]


class UserCredential(BaseModel):
    email: EmailStr
    password: SecretStr  


class UserCreate(BaseModel):
    username: Username
    email: EmailStr
    password: SecurePassword
    otp: str


class UpdatePassword(BaseModel):
    new_password: SecurePassword
    old_password: SecretStr
    


class ForgotPassword(BaseModel):  
    email: EmailStr
    new_password: SecurePassword
    otp: str  