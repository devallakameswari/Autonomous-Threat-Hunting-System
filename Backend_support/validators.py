"""
Backend_support/validators.py
Input validation for forms and API payloads.
"""

import re
from Backend_support.security import is_strong_password

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")


def validate_registration(username, email, password, confirm_password):
    errors = []

    if not USERNAME_REGEX.match(username or ""):
        errors.append(
            "Username must be 3-30 characters (letters, numbers, dot, dash, underscore)."
        )

    if not EMAIL_REGEX.match(email or ""):
        errors.append("Please enter a valid email address.")

    if not is_strong_password(password or ""):
        errors.append("Password must be 8+ characters with letters and numbers.")

    if password != confirm_password:
        errors.append("Passwords do not match.")

    return errors


def validate_ip_address(ip: str) -> bool:
    pattern = re.compile(
        r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    )
    match = pattern.match(ip or "")
    if not match:
        return False
    return all(0 <= int(part) <= 255 for part in match.groups())


def validate_upload_request(files_dict, form_dict=None):
    """Basic guard used by the upload route before touching disk."""
    if "logfile" not in files_dict:
        return "No file part in request."
    file_storage = files_dict["logfile"]
    if file_storage.filename == "":
        return "No file selected."
    return None
