from flask import Blueprint, jsonify, make_response
from flask_pydantic import validate
from http import HTTPStatus

from app.decorators import require_api_key, login_required
from app.utils import*
from app.user_api.models import* 
from app.extension import limiter
from app.oauth2 import create_access_token


logger = logging.getLogger(__name__)

auth = Blueprint("auth", __name__, url_prefix="/auth")

@auth.route("/signin", methods=["POST"])
@require_api_key
@limiter.limit(
    "5 per 5 minutes, 25 per day",
    key_func= get_username_for_rate_limit, 
    error_message="Too many attempts for this account. Try again later."
)
@validate(form=UserCredential)
def signin(form:UserCredential):
    
    is_valid_user, username, email = verify_user(form.email, form.password.get_secret_value())
    if not is_valid_user:
        return jsonify({"message": "Invalid credentials"}), HTTPStatus.UNAUTHORIZED

    try:
        token = create_access_token({"user_id": form.email})
    except Exception as e:
        logger.error(f"Token creation failed: {e}")
        return jsonify({"message": "Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR

    # Create response
    resp = make_response(
        jsonify({"message": "Login successful", "username": username, "email":email}), HTTPStatus.OK
    )

    resp.set_cookie(
        key="access_token",
        value=token,
        max_age=7 * 24 * 60 * 60,
        # expires=timedelta(days=7),
        path="/",
        httponly=True,
        secure=False, # set this true after testing
        samesite="LAX",
    )
    return resp

@auth.route("/reset_password", methods=["PUT"])
@login_required
@validate(body=UpdatePassword)
def reset_password(curr_user, body:UpdatePassword):
    if not curr_user:
        return jsonify({"message": "Unable to process"}), HTTPStatus.BAD_REQUEST
    
    is_valid_old_password = verify_user(curr_user, body.old_password.get_secret_value())[0]
    if not is_valid_old_password:
        return jsonify({"message": "Password not matched"}), HTTPStatus.NOT_FOUND

    if not update_password(curr_user, body.new_password):
        return jsonify({"message": "Details not found"}), HTTPStatus.NOT_FOUND

    return jsonify({"message": "password updated"}), HTTPStatus.OK


@auth.route("/signup", methods=["POST"])
@require_api_key
@validate(body=UserCreate)
def signup(body:UserCreate):
    user_found = user_exists(body.email)
    if user_found:
        return jsonify({"message":"Invalid mail"}), HTTPStatus.CONFLICT
    if not create_user(body.email, body.username, body.password):
        return jsonify({"message": "error occured, Try somtime later"}), HTTPStatus.INTERNAL_SERVER_ERROR
    
    return jsonify({"message": f"User created, username:{body.username}, email:{body.email}"}), HTTPStatus.CREATED


@auth.route("/forgot_password",methods=["POST"])
@require_api_key
@validate(body=ForgotPassword)
def forgot_password(body:ForgotPassword):   
    if not update_password(body.email, body.new_password):
        return jsonify({"error": "Occured"}), HTTPStatus.INTERNAL_SERVER_ERROR

    return jsonify({"message": "password updated"}), HTTPStatus.OK


@auth.route("/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"message": "Logged out successfully"}))

    # Clear the JWT cookie
    resp.delete_cookie(
        key="access_token_cookie", path="/", httponly=True, secure=True, samesite="Lax"
    )

    return resp, HTTPStatus.OK

@auth.route("/send_otp/<otp_for>", methods=["POST"])
@require_api_key
@validate(body=SendOTP)
def send_otp(body: SendOTP, otp_for: str = "signup"):
    """
    Send OTP for signup or password reset.
    
    - signup: fails if user already exists
    - forgot_password: always returns success (does not reveal user existence)
    """
    valid_otp_types = {"signup", "forgot_password"}
    if otp_for not in valid_otp_types:
        return jsonify({"message": "Invalid OTP purpose"}), HTTPStatus.BAD_REQUEST

    email = body.email  

    user_found = user_exists(email)

    if otp_for == "signup" and user_found:
        return jsonify({"message": "User already exists"}), HTTPStatus.CONFLICT

    if otp_for == "forgot_password" and not user_found:
        return jsonify({"message": "OTP sent successfully"}), HTTPStatus.BAD_REQUEST

    success = sendOtp(email)
    if not success:
        return (
            jsonify({"message": "Failed to send OTP. Please try again later."}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    return jsonify({"message": "OTP sent successfully"}), HTTPStatus.OK

@auth.route("/verify_otp", methods=["POST"])
@require_api_key
@validate(body=VerifyOTP)
def verify_otp(body:VerifyOTP):
    email = body.email
    otp = body.otp
    
    is_valid_otp = verify_user_otp(email, otp)
    if not is_valid_otp:
        return jsonify({"message":"Incorrect OTP or OTP Expired"}),HTTPStatus.BAD_REQUEST
    return jsonify({"message":"OTP verified"}), HTTPStatus.OK

@auth.route("/get_profile", methods=["GET"])
@require_api_key
@login_required
def get_profile(curr_user):
    username = get_user_profile(curr_user)
    if not username:
        return jsonify({"message":"Profile not found"}), HTTPStatus.NOT_FOUND
    return jsonify({"email":curr_user, "username":username}), HTTPStatus.OK