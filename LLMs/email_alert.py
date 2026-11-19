"""
LLMs/email_alert.py

Compatibility wrapper for the central email service.

IMPORTANT
---------
The actual email implementation lives in:

    Email_Alerts/email_alert.py

This wrapper exists so older project modules that import:

    from LLMs.email_alert import ...

continue working without maintaining a second SMTP implementation.
"""


# ================================================================
# IMPORT CENTRAL EMAIL SERVICE
# ================================================================

from Email_Alerts.email_alert import (
    EmailAlert,
    email_alert,
    send_email,
    send_registration_otp,
    send_threat_alert_email,
    should_alert,
)


# ================================================================
# PUBLIC EXPORTS
# ================================================================

__all__ = [
    "EmailAlert",
    "email_alert",
    "send_email",
    "send_registration_otp",
    "send_threat_alert_email",
    "should_alert",
]