from pydantic import BaseModel, EmailStr, field_validator, SecretStr
from app.utils import validate_password

class UserCredential(BaseModel):
    email:EmailStr
    password:str
    api_key:str
    
class UserCreate(BaseModel):
    username:str
    email:EmailStr
    password:str
    otp:str
    
    check_password_strength = field_validator('password')(validate_password)

    
    

