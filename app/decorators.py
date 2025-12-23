from functools import wraps
from flask import request, jsonify
from jose import ExpiredSignatureError, JWTError
import logging

from app.oauth2 import verify_access_token
from app.config import settings

logger = logging.getLogger(__name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({"message": "Login required"}), 401
        try:
            token_data = verify_access_token(token)
            kwargs['curr_user'] = token_data.get("email")
            kwargs['username'] = token_data.get("username")

        except ExpiredSignatureError:
            return jsonify({"message":"Token has expired"}),401
        except JWTError:
            return jsonify({"message":"Invalid token"}),401
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {e}")
            return jsonify({"message": "Token verification failed"}), 401
        
        return f(*args, **kwargs)  

    return decorated_function

def require_api_key(f):
    """
    Decorator to protect routes with API key authentication.
    Checks for API key in headers (preferred) or falls back to JSON body/form.
    Priority: Headers 
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Preferred: Check headers (X-API-Key or Authorization: Bearer)
        auth_header = request.headers.get("Authorization")
        x_api_key = request.headers.get("X-API-Key")

        provided_key = None

        if x_api_key:
            provided_key = x_api_key
        elif auth_header and auth_header.startswith("Bearer "):
            provided_key = auth_header.split(" ")[1]

        # 2. Validate the key
        expected_key = settings.api_key  

        if not provided_key:
            return jsonify({"error": "Missing API key"}), 401

        if provided_key != expected_key:
            return jsonify({"error": "Invalid API key"}), 401

        return f(*args, **kwargs)

    return decorated_function