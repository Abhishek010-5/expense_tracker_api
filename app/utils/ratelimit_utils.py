from flask import request

def get_username_for_rate_limit():
    username = request.form.get("username") or request.form.get("email") or "unknown"
    return f"user:{username.lower().strip()}"