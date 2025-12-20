import string

def password_strength(cls, v:str):
    # Check for 8+ chars, uppercase, lowercase, digit, and special character
    special_chars = set(string.punctuation)
    if (
        len(v) < 8 or
        not any(c.isupper() for c in v) or
        not any(c.islower() for c in v) or  
        not any(c.isdigit() for c in v) or
        not any(c in special_chars for c in v)
    ):
        raise ValueError("Password must be 8+ chars with at least one uppercase, one lowercase, one digit, and one special character")
    return v