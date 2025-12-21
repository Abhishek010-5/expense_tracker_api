from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator, PositiveInt
from typing import Annotated
from app.validators import password_strength

Username = Annotated[
    str,
    Field(
        min_length=3,
        max_length=30,
        description="Username must be between 3 and 30 characters",
    ),
]



class UserCredential(BaseModel):
    email: EmailStr
    password: SecretStr  


class UserCreate(BaseModel):
    username: Username
    email: EmailStr
    password: str
    otp: str

    _check_password_strength = field_validator("password")(password_strength)
    
class UpdatePassword(BaseModel):
    new_password: str
    old_password: SecretStr
    
    _check_password_strength = field_validator("new_password")(password_strength)

class ForgotPassword(BaseModel):  
    email: EmailStr
    new_password: str
    
    _check_password_strength = field_validator("new_password")(password_strength)

class SendOTP(BaseModel):
    email:EmailStr
    
class ExpenseCreate(BaseModel):
    amount:PositiveInt
    payment_for:str
    payment_type:str
    description:str | None = None
    tag:str

class VerifyOTP(BaseModel):
    email:EmailStr
    otp:Annotated[str,Field(min_length=6, max_length=6)]
