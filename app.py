from __future__ import annotations

import os
import secrets
import string
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


def password_strength(password: str) -> dict:
    checks = {
        "length_12_plus": len(password) >= 12,
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() for c in password),
    }
    score = sum(checks.values())
    label = "Weak" if score <= 2 else "Moderate" if score <= 3 else "Strong" if score == 4 else "Very strong"
    return {"score": score, "label": label, "checks": checks, "length": len(password)}


def generate_password(length: int = 18) -> str:
    length = max(12, min(int(length), 64))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if password_strength(value)["score"] == 5:
            return value


def validate_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Provide a valid http:// or https:// URL")
    return value.strip()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "Cyber Guard Pro"})


@app.post("/api/password/generate")
def password_api():
    payload = request.get_json(silent=True) or {}
    try:
        length = int(payload.get("length", 18))
    except (TypeError, ValueError):
        return jsonify({"error": "length must be an integer"}), 400
    password = generate_password(length)
    return jsonify({"password": password, "assessment": password_strength(password)})


@app.post("/api/password/check")
def check_api():
    payload = request.get_json(silent=True) or {}
    password = payload.get("password")
    if not isinstance(password, str):
        return jsonify({"error": "password must be a string"}), 400
    return jsonify(password_strength(password))


@app.post("/api/url/scan")
def scan_url():
    payload = request.get_json(silent=True) or {}
    try:
        url = validate_url(str(payload.get("url", "")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return jsonify({"error": "VirusTotal API key is not configured", "hint": "Set VIRUSTOTAL_API_KEY in your local .env file."}), 503
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": api_key}, data={"url": url}, timeout=20,
        )
        response.raise_for_status()
        analysis_id = response.json().get("data", {}).get("id")
        return jsonify({
            "status": "submitted", "analysis_id": analysis_id,
            "message": "URL submitted to VirusTotal. The analysis result can be retrieved separately using this ID.",
        }), 202
    except requests.RequestException as exc:
        app.logger.warning("VirusTotal request failed: %s", exc)
        return jsonify({"error": "VirusTotal request failed", "detail": str(exc)}), 502


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large"}), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")), debug=False)
