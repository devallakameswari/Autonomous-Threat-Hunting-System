"""
Backend_support/api_response.py
Standardized JSON response helpers so every API endpoint returns
a consistent shape: {success, data, message, error}.
"""

from flask import jsonify


def success_response(data=None, message="OK", status_code=200):
    payload = {"success": True, "message": message, "data": data}
    return jsonify(payload), status_code


def error_response(message="An error occurred", status_code=400, error=None):
    payload = {"success": False, "message": message, "error": error}
    return jsonify(payload), status_code
