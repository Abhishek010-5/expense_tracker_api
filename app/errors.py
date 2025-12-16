# app/errors.py
from flask import jsonify
from werkzeug.exceptions import HTTPException

def init_error_handlers(app):
    """
    Register all custom error handlers for the app.
    Call this function inside create_app().
    """

    @app.errorhandler(429)  # Rate limit exceeded (Flask-Limiter)
    def ratelimit_handler(e):
        message = getattr(e, 'description', 'Too many requests. Please try again later.')
        response = jsonify({
            "error": "Rate limit exceeded",
            "message": message,
            "retry_after": getattr(e, 'retry_after', None)
        })
        response.status_code = 429
        return response

    @app.errorhandler(404)  # Page not found
    def not_found_handler(e):
        return jsonify({
            "error": "Not found",
            "message": "The requested resource does not exist."
        }), 404

    # @app.errorhandler(400)  # Bad request
    # def bad_request_handler(e):
    #     return jsonify({
    #         "error": "Bad request",
    #         "message": str(e.description if hasattr(e, 'description') else e)
    #     }), 400

    @app.errorhandler(401)  # Unauthorized
    def unauthorized_handler(e):
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required."
        }), 401

    @app.errorhandler(403)  # Forbidden
    def forbidden_handler(e):
        return jsonify({
            "error": "Forbidden",
            "message": "You do not have permission to access this resource."
        }), 403

    @app.errorhandler(500)  # Internal server error
    def internal_error_handler(e):
        app.logger.error(f"Server Error: {e}")  # Log the full error
        return jsonify({
            "error": "Internal server error",
            "message": "Something went wrong on our end. Please try again later."
        }), 500

    # Optional: Catch-all for other HTTP exceptions
    @app.errorhandler(HTTPException)
    def http_exception_handler(e):
        if e.code in [429, 404, 400, 401, 403, 500]:
            return  # Let specific handlers above take priority
        return jsonify({
            "error": e.name,
            "message": e.description
        }), e.code