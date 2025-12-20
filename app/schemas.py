from pydantic import BaseModel, EmailStr, field_validator, SecretStr, Field
from app.utils import strong_password_validator
from typing import Annotated

Username = Annotated[str, Field(min_length=3, max_length=30)]
Password = Annotated[str, Field(min_length=8, max_length=256)]

class UserCredential(BaseModel):
    email:EmailStr
    password:str
    
class UserCreate(BaseModel):
    username:Username
    email:EmailStr
    password:Password
    otp:str
    
    check_password_strength = strong_password_validator("password")

class UpdatePassword(BaseModel):
    new_password:Password
    old_password:Password
    
    check_new_password_strength = strong_password_validator("new_password")

class  FogotPassword(BaseModel):
    email:EmailStr
    new_password:Password
    opt:str
    
    check_new_password_strength = strong_password_validator("new_password")