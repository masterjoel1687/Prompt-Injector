from flask import Blueprint, jsonify, request

from backend.engine.retest import RetestEngine
from backend.engine.tester import PromptInjectionTester


scan_bp = Blueprint("scan", __name__)


# =========================================================
# SECURITY SCAN
# =========================================================

@scan_bp.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(
        silent=True
    ) or {}

    endpoint = data.get("endpoint")

    if not endpoint:
        return jsonify({
            "error": "Target endpoint is required."
        }), 400

    provider = data.get(
        "provider",
        "generic"
    )

    model = data.get("model")

    headers = data.get(
        "headers",
        {}
    )

    api_key = data.get(
        "api_key"
    )

    tester = PromptInjectionTester(
        provider=provider,
        endpoint=endpoint,
        model=model,
        headers=headers,
        api_key=api_key,
    )

    result = tester.run_scan()

    return jsonify(result)


# =========================================================
# ATTACK -> FIX -> RETEST
# =========================================================

@scan_bp.route("/api/retest", methods=["POST"])
def retest():
    data = request.get_json(
        silent=True
    ) or {}

    endpoint = data.get("endpoint")

    if not endpoint:
        return jsonify({
            "error": "Target endpoint is required."
        }), 400

    baseline = data.get("baseline")

    if not baseline:
        return jsonify({
            "error": (
                "Baseline scan results are required "
                "for retesting."
            )
        }), 400

    if not isinstance(baseline, dict):
        return jsonify({
            "error": "Baseline must be a JSON object."
        }), 400

    provider = data.get(
        "provider",
        "generic"
    )

    model = data.get("model")

    headers = data.get(
        "headers",
        {}
    )

    api_key = data.get(
        "api_key"
    )

    try:
        engine = RetestEngine(
            provider=provider,
            endpoint=endpoint,
            model=model,
            headers=headers,
            api_key=api_key,
        )

        result = engine.run_retest(
            baseline
        )

        return jsonify(result)

    except Exception as exc:
        return jsonify({
            "error": "Retest failed.",
            "details": str(exc),
        }), 500