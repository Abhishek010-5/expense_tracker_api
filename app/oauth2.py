from jose import jwt, JWTError
from config import settings
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
    
def verify_access_token(token:str, credentails_expectation):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id:str = payload.get("user_id")
        
        if id is None:
            raise credentails_expectation
        token_data = id
    except JWTError as e:
        print(e)
        raise credentails_expectation
    except AssertionError as e:
        print(e)
        raise credentails_expectation
    return token_data

