from flask import Flask
from flask_cors import CORS

from backend.config import Config
from backend.routes.health import health_bp
from backend.routes.scan import scan_bp


def create_app():
    """Create and configure the Flask application."""

    app = Flask(__name__)

    app.config.from_object(Config)

    CORS(app)

    app.register_blueprint(health_bp)
    app.register_blueprint(scan_bp)

    @app.route("/")
    def index():
        return {
            "name": "AI Prompt Injection Tester",
            "version": "3.0",
            "status": "running"
        }

    return app