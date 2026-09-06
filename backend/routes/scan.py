import json
from pathlib import Path
from flask import Blueprint, jsonify, request
import requests

from backend.engine.retest import RetestEngine
from backend.engine.tester import PromptInjectionTester


scan_bp = Blueprint("scan", __name__)


# =========================================================
# TEST SUITES METADATA
# =========================================================

@scan_bp.route("/api/suites", methods=["GET"])
def get_suites():
    """Return available benchmark suites, categories, and attack counts."""
    path = Path(__file__).resolve().parent.parent / "attacks" / "attacks.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            attacks = json.load(f)
    except Exception as exc:
        return jsonify({"error": f"Failed to load attacks: {exc}"}), 500

    smoke_count = sum(1 for a in attacks if "smoke" in a.get("suites", []))
    owasp_count = sum(1 for a in attacks if "owasp" in a.get("suites", []))
    total_count = len(attacks)

    categories = sorted(list(set(a.get("category", "General") for a in attacks)))
    owasp_categories = sorted(list(set(a.get("owasp", "General") for a in attacks if a.get("owasp"))))

    return jsonify({
        "suites": {
            "smoke": {
                "name": "Quick Smoke Test",
                "count": smoke_count,
                "description": "Fast 10-15s demo scan covering high-impact prompt injection vectors",
            },
            "owasp": {
                "name": "OWASP LLM Top 10 Suite",
                "count": owasp_count,
                "description": "Standardized compliance battery mapped to OWASP LLM01, LLM02, and LLM06",
            },
            "comprehensive": {
                "name": "Full Red-Team Battery",
                "count": total_count,
                "description": "Deep multi-vector penetration test across 72 creative injection techniques",
            },
        },
        "total_attacks": total_count,
        "categories": categories,
        "owasp_categories": owasp_categories,
    })


# =========================================================
# SECURITY SCAN
# =========================================================

@scan_bp.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    endpoint = data.get("endpoint")
    if not endpoint:
        return jsonify({"error": "Target endpoint is required."}), 400

    provider = data.get("provider", "generic")
    model = data.get("model")
    headers = data.get("headers", {})
    api_key = data.get("api_key")
    suite = data.get("suite", "smoke")
    categories = data.get("categories")

    try:
        tester = PromptInjectionTester(
            provider=provider,
            endpoint=endpoint,
            model=model,
            headers=headers,
            api_key=api_key,
            suite=suite,
            categories=categories,
        )

        result = tester.run_scan()
        return jsonify(result)

    except Exception as exc:
        return jsonify({
            "error": "Scan execution failed.",
            "details": str(exc),
        }), 500


# =========================================================
# INTERACTIVE PLAYGROUND (SINGLE TEST)
# =========================================================

@scan_bp.route("/api/test-single", methods=["POST"])
def test_single():
    data = request.get_json(silent=True) or {}

    endpoint = data.get("endpoint")
    if not endpoint:
        return jsonify({"error": "Target endpoint is required."}), 400

    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Attack prompt is required."}), 400

    provider = data.get("provider", "generic")
    model = data.get("model")
    headers = data.get("headers", {})
    api_key = data.get("api_key")
    metadata = data.get("metadata", {})

    try:
        tester = PromptInjectionTester(
            provider=provider,
            endpoint=endpoint,
            model=model,
            headers=headers,
            api_key=api_key,
        )

        result = tester.test_single(prompt, metadata)
        return jsonify({
            "status": "completed",
            "result": result,
        })

    except Exception as exc:
        return jsonify({
            "error": "Single test execution failed.",
            "details": str(exc),
        }), 500


# =========================================================
# ATTACK -> FIX -> RETEST
# =========================================================

@scan_bp.route("/api/retest", methods=["POST"])
def retest():
    data = request.get_json(silent=True) or {}

    endpoint = data.get("endpoint")
    if not endpoint:
        return jsonify({"error": "Target endpoint is required."}), 400

    baseline = data.get("baseline")
    if not baseline or not isinstance(baseline, dict):
        return jsonify({
            "error": "Valid baseline scan results are required for retesting."
        }), 400

    provider = data.get("provider", "generic")
    model = data.get("model")
    headers = data.get("headers", {})
    api_key = data.get("api_key")
    suite = data.get("suite")

    try:
        engine = RetestEngine(
            provider=provider,
            endpoint=endpoint,
            model=model,
            headers=headers,
            api_key=api_key,
            suite=suite,
        )

        result = engine.run_retest(baseline)
        return jsonify(result)

    except Exception as exc:
        return jsonify({
            "error": "Retest failed.",
            "details": str(exc),
        }), 500


# =========================================================
# TARGET DEFENSE GUARDRAIL PROXY (FOR LIVE DEMO)
# =========================================================

@scan_bp.route("/api/target/toggle-defense", methods=["POST"])
def proxy_toggle_defense():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "http://127.0.0.1:5001/defense/toggle")

    try:
        resp = requests.post(target_url, timeout=5)
        return jsonify(resp.json())
    except Exception as exc:
        return jsonify({
            "error": "Could not connect to target defense control endpoint.",
            "details": str(exc),
        }), 502


@scan_bp.route("/api/target/defense", methods=["GET"])
def proxy_get_defense():
    target_url = request.args.get("target_url", "http://127.0.0.1:5001/defense")

    try:
        resp = requests.get(target_url, timeout=5)
        return jsonify(resp.json())
    except Exception as exc:
        return jsonify({
            "error": "Could not fetch target defense status.",
            "details": str(exc),
        }), 502