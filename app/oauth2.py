from jose import jwt, JWTError, ExpiredSignatureError
from app.config import settings
from datetime import datetime, timedelta

SECRET_KEY =  settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRES_IN_MINUTES = settings.access_token_expire_minutes

def create_access_token(data:dict):
    to_encode = data.copy()
    expiers = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN_MINUTES)
    to_encode.update({'exp':expiers})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
    
def verify_access_token(token:str)->dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email:str = payload.get("user_id")
        username:str = payload.get("username")
        
        if id is None:
            raise JWTError("Missing user_id in token")
        token_data = {"email":email,"username":username}
        
    except ExpiredSignatureError:
            raise ExpiredSignatureError("Token has expired")
    except JWTError as e:
            raise JWTError(f"Invalid token: {str(e)}")
    return token_data

