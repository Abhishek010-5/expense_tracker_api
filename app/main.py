from flask import Flask, send_from_directory
from flask_cors import CORS
import logging
import os

from app.config import settings
from app.routes import auth, expense
from app.extension import limiter
from app.errors import init_error_handlers


def create_app():
    app = Flask(__name__)
    
    # clear default handlers to avoid duplicates
    app.logger.handlers.clear()
    
    # Configure the ROOT logger (this affects all loggers created with getLogger(__name__))
    root_logger = logging.getLogger()  # Gets the root logger
    root_logger.handlers.clear()       # Clear any existing handlers (e.g., from Flask)
    
    # Create and configure console handler
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    console_handler.setFormatter(formatter)
    
    root_logger.addHandler(console_handler)
    
    # Set log level based on environment
    if os.getenv('VERCEL') or not app.debug:
        root_logger.setLevel(logging.INFO)
        app.logger.info("Log level set to INFO (Production/Vercel mode)")
    else:
        root_logger.setLevel(logging.DEBUG)
        app.logger.info("Log level set to DEBUG (Development mode)")
        
    # Ensure propagation is enabled (default is True, but good to be explicit)
    root_logger.propagate = True
    
    # # Log startup info
    app.logger.info("Flask application initialized")
    app.logger.info(f"Running in {'Production (Vercel)' if os.getenv('VERCEL') else 'Development'} mode")
    
    CORS(app,origins="*")
    # Bind the limiter to the app AFTER creation
    limiter.init_app(app)

    # Now set global defaults (after init_app)
    limiter.default_limits = ["200 per day", "50 per hour"]

    # Optional: headers
    limiter.headers_enabled = True
    
    app.register_blueprint(auth)
    app.register_blueprint(expense)

    @app.route("/", methods=["GET"])
    @limiter.exempt
    def root():
        return {"message": "API is working"}
    
    @app.route('/favicon.ico')
    @app.route('/favicon.png')
    @limiter.exempt
    def favicon():
        try:
            return send_from_directory(app.static_folder, 'icons8-favicon-50.png')
        except FileNotFoundError:
            return '', 204  
        
    # Register all error handlers in one line
    init_error_handlers(app)

    return app


app = create_app()
    
