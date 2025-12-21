from app.utils import*
from app.oauth2 import create_access_token
from app.decorators import login_required, require_api_key
from app.extension import limiter
from app.schemas import*

from flask import jsonify, request, make_response, Blueprint
from flask_pydantic import validate
from datetime import datetime

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
    
    is_valid_user, username = verify_user(form.email, form.password.get_secret_value())
    if not is_valid_user:
        return jsonify({"message": "Invalid credentials"}), 401

    try:
        token = create_access_token({"email": form.email})
    except Exception as e:
        print(f"Token creation failed: {e}")
        return jsonify({"message": "Internal server error"}), 500

    # Create response
    resp = make_response(
        jsonify({"message": "Login successful", "username": username, "email":form.email}), 200
    )

    resp.set_cookie(
        key="access_token",
        value=token,
        max_age=7 * 24 * 60 * 60,
        # expires=timedelta(days=7),
        path="/",
        httponly=True,
        secure=True,
        samesite="LAX",
    )
    return resp

@auth.route("/reset_password", methods=["PUT"])
@login_required
@validate(body=UpdatePassword)
def reset_password(curr_user, body:UpdatePassword):
    # if not request.json:
        # return {"message": "Request must contain json"}, 400
    # data = request.get_json()
    # if not data or data == {}:
        # return {"message": "Request cannot be empty"}, 400

    # old_password = data.get("old_password")
    # new_password = data.get("new_password")

    # if not old_password or not new_password:
        # return jsonify({"message": "old and new password required"}), 400

    # if not validate_password(new_password):
    #     return (
    #         jsonify(
    #             {
    #                 "message": "Password must be 8+ chars with at least one uppercase, one lowercase, one digit, and one special character"
    #             }
    #         ),
    #         400,
    #     )

    if not curr_user:
        return jsonify({"message": "Unable to process"}), 400
    
    is_valid_old_password = verify_user(curr_user, body.old_password.get_secret_value())[0]
    if not is_valid_old_password:
        return jsonify({"message": "Password not matched"}), 404

    if not update_password(curr_user, body.new_password):
        return jsonify({"message": "Details not found"}), 404

    return jsonify({"message": "password updated"}), 200


@auth.route("/signup", methods=["POST"])
@require_api_key
@validate(body=UserCreate)
def signup(body:UserCreate):
    
    if user_exists(body.email):
        return jsonify({"message":"users alredy exixts"}),400
    
    if not verify_user_otp(body.email,body.otp):
        return jsonify({"message":"Incorrect otp"}),400

    if not create_user(body.email, body.username, body.password):
        return jsonify({"message": "error occured, Try somtime later"}), 500
    
    return jsonify({"message": f"User created, username:{body.username}, email:{body.email}"}), 200


@auth.route("/forogt_password")
@require_api_key
@validate(body=ForgotPassword)
def forgot_password(body:ForgotPassword):
    # if not request.json:
        # return jsonify({"message": "request cannot be empty"}), 400
    # data = request.get_json()
    # email = data.get("email")
    # new_password = data.get("new_password")

    # if not email or not new_password:
        # return jsonify({"message": "request must contain email or new password"}), 400
    # if not validate_email(email):
        # return jsonify({"message": "Invalid email format"}), 400
    # if not (new_password):
        # return jsonify({"message": "Invalid password format"}), 400
    if not user_exists(body.email):
        return jsonify({"message": "Invalid credentials"}), 404
    
    is_valid_otp = verify_user_otp(body.email, body.otp)
    if not is_valid_otp:
        return jsonify({"message":"Incorrect OTP"}),400
    
    if not update_password(body.email, body.new_password):
        return jsonify({"error": "Occured"}), 500

    return jsonify({"message": "password updated"}), 200


@auth.route("/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"message": "Logged out successfully"}))

    # Clear the JWT cookie
    resp.delete_cookie(
        key="access_token_cookie", path="/", httponly=True, secure=True, samesite="Lax"
    )

    return resp, 200

@auth.route("/send_otp/signup", methods=["POST"])
@require_api_key
@validate(body=SendOTP)
def send_otp(body:SendOTP):
    # if not request.json:
        # return jsonify({"message": "request cannot be empty"}), 400
    # data = request.get_json()
    # if not data:
        # return jsonify({"message": "json should contain email"}), 400

    # email = data.get("email")
    
    # if not email:
        # return jsonify({"message":"email is required"}),400

    # if not validate_email(email):
        # return jsonify({"message": "invalid email format"}), 422
    # if not user_exists(email):
    #     return jsonify({"message": "Unauthorized"}), 401
    email = body.email
    if user_exists(email):
        return jsonify({"message":"User already exists"}),400
    if not sendOtp(email):
        return jsonify({"message": "unable able to send otp, please try later"}), 500
    return jsonify({"message": "OPT snet"}), 200

@auth.route('/send_otp/forgot_password', methods=["POST"])
@require_api_key
@validate(body=SendOTP)
def send_otp_fog(body:SendOTP):
    
    email = body.email
    if not user_exists(email):
        return ({"message":"Invalid eamil"}), 400
    if not sendOtp(email):
        return jsonify({"message": "unable able to send otp, please try later"}), 500
    return jsonify({"message": "OPT snet"}), 200
        

expense = Blueprint('expense', __name__, url_prefix='/expenses')

@expense.route("/add_expense", methods=["POST"])
@login_required
@validate(body=ExpenseCreate)
def add_expense(curr_user, body:ExpenseCreate):
    # if not request.json:
        # return jsonify({"message": "Request must be JSON"}), 400
    # expense_data = request.get_json()

    # if not expense_data:
        # return jsonify({"message": "Request must contain JSON data"}), 400

    # amount = expense_data.get("amount")
    # payment_type = expense_data.get("payment_type")
    # payment_for = expense_data.get("payment_for")
    # description = expense_data.get("description")

    # if not all([amount, payment_type, payment_for]):
        # return (
            # jsonify({"message": "Amount, payment type, or payment for is missing"}),
            # 400,
        # )

    # if not isinstance(amount, int):
        # return (
            # jsonify(
                # {
                    # "message": f"Amount should be of type int, but received {type(amount).__name__}"
                # }
            # ),
            # 400,
        # )

    # if not isinstance(payment_type, str) or not isinstance(payment_for, str):
        # return (
            # jsonify({"message": "Payment type and payment for must be of type str"}),
            # 400,
        # )

    curr_date = datetime.today().replace(hour=0, minute=0,second=0,microsecond=0)

    expense_detail = {
        "date": curr_date,
        "email": curr_user,
        "amount": body.amount,
        "payment_type": body.payment_type,
        "payment_for": body.payment_for,
        "description":body.description,
        "tag":body.tag
    }

    if not add_user_expense(expense_detail):
        return jsonify({"message": "An error occurred while adding expense"}), 500

    return jsonify({"message": "Expense added successfully"}), 200


@expense.route("/get_expense", methods=["GET"])
@require_api_key
@login_required
def get_expense(curr_user):
    expenses = get_user_expense(curr_user)

    if expenses is None:
        return jsonify({"message": "Failed to retrieve expenses"}), 500

    if not expenses:
        return jsonify({"data": []}), 200

    return jsonify({"data": expenses}), 200


@expense.route("/get_curr_year_expense", methods=["GET"])
@login_required
def get_curr_year_expense(curr_user):
    expense = get_user_curr_year_expense(curr_user)

    if expense is None:
        return jsonify({"message": "Failed to retrieve expenses"}), 500

    total_amount = expense[0].get("total_amount")
    return jsonify({"total_amount": total_amount})
