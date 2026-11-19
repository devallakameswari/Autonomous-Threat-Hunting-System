"""
Backend_support/security.py
Small security utility helpers: password strength checks, token generation,
and simple text sanitization used before storing/rendering log content.
"""

import re
import secrets
import html


def is_strong_password(password: str) -> bool:
    """Requires 8+ chars, at least one letter and one digit."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True


def generate_secure_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sanitize_for_display(text: str) -> str:
    """Escapes HTML-special characters so raw log lines can be safely rendered."""
    if text is None:
        return ""
    return html.escape(text)


def mask_sensitive(value: str, keep: int = 4) -> str:
    """Masks all but the last `keep` characters, useful for tokens/keys in logs."""
    if not value:
        return value
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]
