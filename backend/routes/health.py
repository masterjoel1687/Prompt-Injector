from flask import Blueprint

health_bp = Blueprint("health", __name__)


@health_bp.route("/api/health", methods=["GET"])
def health():
    return {
        "service": "AI Prompt Injection Tester",
        "version": "3.0",
        "status": "healthy"
    }