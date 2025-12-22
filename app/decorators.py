from functools import wraps
from flask import request, jsonify

from app.oauth2 import verify_access_token
from app.config import settings



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({"message": "Login required"}), 401

        # Verify token and get the user data
        # Assuming verify_access_token returns a dict with user info, e.g. {"user_id": ..., "email": ...}
        token_data = verify_access_token(token, "error")

        if not token_data:
            return jsonify({"message": "Invalid or expired token"}), 401

        # Pass the verified user data to the route function
        # You can pass it as a keyword argument named "current_user" or whatever you prefer
        kwargs['curr_user'] = token_data  # or token_data.get('curr_user')

        return f(*args, **kwargs)  # <-- important: call the original function!

    return decorated_function


# def require_api_key(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if  request.is_json:
#             data = request.get_json()
#         else:
#             data = request.form
       
        
#         provided_key = data.get('api_key')
#         if request.is_json:
#             data.pop('api_key')
#         if not provided_key:
#             return jsonify({"error": "Missing API key"}), 401
        
#         if provided_key != settings.api_key:
#             return jsonify({"error": "Invalid API key"}), 401
        
        
        
        
#         return f(*args, **kwargs)
    
#     return decorated_function


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

        # 3. All good — proceed
        return f(*args, **kwargs)

    return decorated_function