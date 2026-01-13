from flask import Blueprint, jsonify, request
from pydantic import ValidationError
from pymongo.errors import PyMongoError
from http import HTTPStatus
from flask_pydantic import validate
from datetime import datetime
import logging

from app.utils.expense_utils import*
from app.expense_api.models import*
from app.decorators import login_required, require_api_key

logger = logging.getLogger(__name__)

expense = Blueprint('expense', __name__, url_prefix='/expenses')

@expense.route("/add_expense", methods=["POST"])
@login_required
@validate(body=ExpenseCreate)
def add_expense(curr_user, body:ExpenseCreate):

    curr_date = datetime.today()

    expense_detail = {
        "date": curr_date,
        "email": curr_user,
        "amount": body.amount,
        "payment_type": body.payment_type,
        "payment_for": body.payment_for,
        "description":body.description,
        "tag":body.tag
    }
    try:
        if not add_user_expense(expense_detail):
            return jsonify({"message": "An error occurred while adding expense"}), HTTPStatus.INTERNAL_SERVER_ERROR
    except PyMongoError as dbe:
        logger.error({"Database error":str(dbe)})
        return jsonify({"message":"Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    except Exception as e:
        logger.error({"error":str(e)})
        return jsonify({"message":"Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR

    return jsonify({"message": "Expense added successfully"}), HTTPStatus.OK


@expense.route("/get_expense", methods=["GET"])
@require_api_key
@login_required
def get_expense(curr_user):
    try:
        expenses = get_user_expense(curr_user)
    except PyMongoError as dbe:
        logger.error({"database error":str(dbe)})
        return jsonify({"message":"internal servere erorr"})
    except Exception as e:
        logger.error({"error":str(e)})
        return jsonify({"message":"internal sever error"}), HTTPStatus.INTERNAL_SERVER_ERROR

    if not expenses:
        return jsonify({"data": []}), HTTPStatus.OK

    return jsonify({"data": expenses}), HTTPStatus.OK


@expense.route("/get_curr_year_expense", methods=["GET"])
@login_required
def get_curr_year_expense(curr_user):
    try:
        expense = get_user_curr_year_expense(curr_user)
    except PyMongoError as dbe:
        logger.error({"databse error":str(dbe)})
        return jsonify({"internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    except Exception as e:
        logger.error({"error":str(e)})
        return jsonify({"message":"internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    total_amount = expense[0].get("total_amount")
    return jsonify({"total_amount": total_amount}), HTTPStatus.OK


@expense.route("/weekly", methods=["GET"])
@require_api_key
@login_required
def by_week(curr_user):
    try:
        expenses = get_user_curr_week_expense(curr_user)
        
        
        if expenses is None:
            expenses = []  
        
        return jsonify({
            "expenses": expenses, 
            "total_count": len(expenses),
            "period": "current_week"  
        }), HTTPStatus.OK
        
    except PyMongoError as e:
        logger.error(f"Database error for user {curr_user}: {str(e)}")
        return jsonify({
            "error": "Database error",
            "message": "Failed to retrieve expenses due to a server issue"
        }), HTTPStatus.INTERNAL_SERVER_ERROR

    except Exception as e:
        logger.error({
            "error": "Failed to fetch weekly expenses",
            "user_id": curr_user,
            "exception": str(e)
        })
        return jsonify({
            "error": "Internal server error",
            "message": "Failed to retrieve weekly expenses"
        }), HTTPStatus.INTERNAL_SERVER_ERROR
        
@expense.get("/monthly-avg")
@require_api_key
@login_required
def get_monthly_avg_expense_route(curr_user):
    try:
        query = MonthlyAvgQuery(**request.args)
    except ValidationError as e:
        return jsonify({"error": "Invalid parameters", "details": e.errors()}), HTTPStatus.BAD_REQUEST
    try:
        average = get_user_monthly_avg_expense(email=curr_user, month=query.month, year=query.year)
    except PyMongoError as dbe:
        logger.error({"database error":str(dbe)})
        return jsonify({"message":"internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    except Exception as e:
        logger.error({"error":str(e)})
        return jsonify({"message":"Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    return jsonify({"average_expense": average})

@expense.route("/transaction-summary", methods=["GET"])
@require_api_key
@login_required
def transaction_summary(curr_user:str):
    try:
        query = TransactionSummaryQuery(**request.args)
    except ValidationError as e:
        return jsonify({"error": "Invalid parameters", "details": e.errors()}), HTTPStatus.BAD_REQUEST
    try:
        summary = get_user_transaction_summary(
            curr_user,
            day=query.day,
            month=query.month,
            year=query.year
        )
    except PyMongoError as dbe:
        logger.error({"database error":str(dbe)})
        return jsonify({"message":"internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    except Exception as e:
        logger.error({"error":str(e)})
        return jsonify({"message":"Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    return summary

@expense.route("/month-daily", methods=["GET"])
@require_api_key
@login_required
def months_avg(curr_user):
    try:
        expense_details = get_curr_month_daily_expense(curr_user)
    except ExpenseCreate as e:
        logger.error({"error":str(e)})
        return jsonify({"Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    return expense_details

@expense.route("/payment-methods-and-total", methods=["GET"])
@require_api_key
@login_required
def payment_methods_and_total(curr_user):
    if not curr_user:
        return jsonify({"message":"user not found"}), HTTPStatus.NOT_FOUND
    try:
        expense_details = get_expense_payment_method_and_total(email=curr_user)
        
        if expense_details is None:
            return jsonify({"message":"not details found or not detials exists"}), HTTPStatus.NOT_FOUND
    except Exception as e:
        logger.error({"error":str(e)})
        return jsonify({"message":"Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
    return jsonify(expense_details)