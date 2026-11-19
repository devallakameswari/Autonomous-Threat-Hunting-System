"""
utils/timezone_utils.py

ATHS timezone utilities.

Database/internal time:
    UTC

Display time:
    Asia/Kolkata (IST)
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc
IST = ZoneInfo("Asia/Kolkata")


def utc_to_ist(value):
    if value is None:
        return None

    if not isinstance(value, datetime):
        return value

    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)

    return value.astimezone(IST)


def format_ist(value, fmt="%Y-%m-%d %H:%M:%S"):
    if value is None:
        return "—"

    converted = utc_to_ist(value)

    if not isinstance(converted, datetime):
        return str(converted)

    return converted.strftime(fmt)


def format_ist_with_timezone(value, fmt="%Y-%m-%d %H:%M:%S"):
    if value is None:
        return "—"

    converted = utc_to_ist(value)

    if not isinstance(converted, datetime):
        return str(converted)

    return converted.strftime(fmt) + " IST"
