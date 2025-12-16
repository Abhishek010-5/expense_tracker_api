from flask import Flask
from flask_cors import CORS

from app.config import settings
from routes import auth, expense
from extension import limiter
from errors import init_error_handlers


def create_app():
    app = Flask(__name__)
    CORS(app)
    # Bind the limiter to the app AFTER creation
    limiter.init_app(app)

    # Now set global defaults (after init_app)
    limiter.default_limits = ["200 per day", "50 per hour"]

    # Optional: storage for production redis://default:mysecretpassword@myredis.example.com:6379
    limiter.storage_uri = f"redis://{settings.redis_username}:{settings.redis_password}@{settings.redis_host}:{settings.redis_port}"

    # Optional: headers
    limiter.headers_enabled = True
    
    app.register_blueprint(auth)
    app.register_blueprint(expense)

    @app.route("/", methods=["GET"])
    @limiter.exempt
    def root():
        return {"message": "API is working"}
    # Register all error handlers in one line
    init_error_handlers(app)

    return app

# # Correct way to run
# if __name__ == "__main__":
#     app = create_app()
#     app.run(debug=True)
