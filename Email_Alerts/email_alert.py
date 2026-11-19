"""
Email_Alerts/email_alert.py

Central email service for the Autonomous Threat Hunting System.

Responsibilities
----------------
1. Send autonomous threat alert emails.
2. Send registration authorization OTP emails.
3. Resolve the correct recipient.
4. Apply severity-based alert filtering.
5. Support Gmail SMTP using SSL or STARTTLS.
6. Return clear alert states:
       SENT
       FAILED
       SUPPRESSED
"""

import smtplib
from email.message import EmailMessage
from html import escape
from typing import Optional, Tuple

from flask import has_request_context
from flask_login import current_user

from config import Config


# ================================================================
# SEVERITY ORDER
# ================================================================

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ================================================================
# HELPER
# ================================================================

def _get_config(name, default=None):
    """
    Safely read a configuration value.
    """
    return getattr(Config, name, default)


def _as_bool(value, default=False):
    """
    Convert common environment/config values to boolean.
    """
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in (
        "true",
        "1",
        "yes",
        "on",
    )


def _as_int(value, default):
    """
    Safely convert a value to integer.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ================================================================
# RECIPIENT RESOLUTION
# ================================================================

def _resolve_recipient_email(
    recipient_email: Optional[str] = None,
) -> str:
    """
    Resolve the email recipient.

    Priority:

        1. Explicit recipient_email
        2. LIVE_ALERT_RECIPIENT_EMAIL
        3. Currently authenticated user's email
        4. ALERT_EMAIL_TO
    """

    # ------------------------------------------------------------
    # 1. Explicit recipient
    # ------------------------------------------------------------

    if recipient_email:
        value = str(recipient_email).strip()

        if value:
            return value

    # ------------------------------------------------------------
    # 2. Live/background recipient
    # ------------------------------------------------------------

    live_recipient = str(
        _get_config(
            "LIVE_ALERT_RECIPIENT_EMAIL",
            "",
        )
        or ""
    ).strip()

    if live_recipient:
        return live_recipient

    # ------------------------------------------------------------
    # 3. Logged-in user
    # ------------------------------------------------------------

    if has_request_context():
        try:
            if current_user.is_authenticated:

                user_email = getattr(
                    current_user,
                    "email",
                    None,
                )

                user_email = str(
                    user_email or ""
                ).strip()

                if user_email:
                    return user_email

        except Exception:
            pass

    # ------------------------------------------------------------
    # 4. Configured fallback
    # ------------------------------------------------------------

    configured_email = str(
        _get_config(
            "ALERT_EMAIL_TO",
            "",
        )
        or ""
    ).strip()

    return configured_email


# ================================================================
# ALERT POLICY
# ================================================================

def should_alert(severity: str) -> bool:
    """
    Return True if an email should be sent.

    Example:

        EMAIL_ALERT_MIN_SEVERITY=MEDIUM

        LOW       -> SUPPRESSED
        MEDIUM    -> SENT
        HIGH      -> SENT
        CRITICAL  -> SENT
    """

    # ------------------------------------------------------------
    # Global email switch
    # ------------------------------------------------------------

    enabled = _as_bool(
        _get_config(
            "EMAIL_ALERTS_ENABLED",
            False,
        ),
        False,
    )

    if not enabled:
        return False

    # ------------------------------------------------------------
    # Normalize severity
    # ------------------------------------------------------------

    severity = str(
        severity or "LOW"
    ).strip().upper()

    # ------------------------------------------------------------
    # Minimum severity
    # ------------------------------------------------------------

    minimum_severity = str(
        _get_config(
            "EMAIL_ALERT_MIN_SEVERITY",
            "MEDIUM",
        )
        or "MEDIUM"
    ).strip().upper()

    current_level = SEVERITY_ORDER.get(
        severity,
        0,
    )

    minimum_level = SEVERITY_ORDER.get(
        minimum_severity,
        SEVERITY_ORDER["MEDIUM"],
    )

    return current_level >= minimum_level


# ================================================================
# HTML VALUE HELPER
# ================================================================

def _safe_html(value, default=""):
    """
    Safely convert arbitrary values to HTML-safe text.
    """

    if value is None:
        value = default

    if isinstance(
        value,
        (list, tuple, set),
    ):
        value = ", ".join(
            str(item)
            for item in value
        )

    elif isinstance(
        value,
        dict,
    ):
        value = str(value)

    return escape(str(value))


# ================================================================
# BUILD THREAT HTML
# ================================================================

def _build_html_body(finding: dict) -> str:
    """
    Build the autonomous threat alert HTML email.
    """

    severity = _safe_html(
        finding.get(
            "severity",
            "UNKNOWN",
        ),
        "UNKNOWN",
    )

    title = _safe_html(
        finding.get(
            "title",
            "Threat Detected",
        ),
        "Threat Detected",
    )

    threat_type = _safe_html(
        finding.get(
            "threat_type",
            "Unknown",
        ),
        "Unknown",
    )

    source_ip = _safe_html(
        finding.get(
            "source_ip",
            "Unknown",
        ),
        "Unknown",
    )

    destination_ip = _safe_html(
        finding.get("dest_ip")
        or finding.get("dst_ip")
        or finding.get("destination_ip")
        or "Unknown",
        "Unknown",
    )

    confidence = _safe_html(
        finding.get(
            "confidence",
            "Unknown",
        ),
        "Unknown",
    )

    detection_source = _safe_html(
        finding.get(
            "detection_source",
            "Unknown",
        ),
        "Unknown",
    )

    mitre_techniques = _safe_html(
        finding.get("mitre_techniques")
        or finding.get("mitre")
        or "Not mapped",
        "Not mapped",
    )

    description = _safe_html(
        finding.get(
            "description",
            "No description available.",
        ),
        "No description available.",
    )

    llm_summary = _safe_html(
        finding.get(
            "llm_summary",
            "No AI analyst summary available.",
        ),
        "No AI analyst summary available.",
    )

    evidence = _safe_html(
        finding.get(
            "evidence",
            "",
        ),
        "",
    )

    recommendation = _safe_html(
        finding.get(
            "recommendation",
            "",
        ),
        "",
    )

    # ------------------------------------------------------------
    # Evidence block
    # ------------------------------------------------------------

    evidence_block = ""

    if evidence.strip():

        evidence_block = f"""
        <p>
            <strong>Evidence:</strong>
        </p>

        <div style="
            background:#f8fafc;
            border:1px solid #e2e8f0;
            border-radius:6px;
            padding:12px;
            white-space:pre-wrap;
            word-break:break-word;
        ">
            {evidence}
        </div>
        """

    # ------------------------------------------------------------
    # Recommendation block
    # ------------------------------------------------------------

    recommendation_block = ""

    if recommendation.strip():

        recommendation_block = f"""
        <p>
            <strong>Recommendation:</strong>
        </p>

        <p>
            {recommendation}
        </p>
        """

    # ------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------

    return f"""
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <title>
        Autonomous Threat Alert
    </title>

</head>

<body style="
    margin:0;
    padding:20px;
    background:#f8fafc;
    font-family:Arial,Helvetica,sans-serif;
    color:#0f172a;
">

    <div style="
        max-width:700px;
        margin:auto;
        background:#ffffff;
        border:1px solid #e2e8f0;
        border-radius:10px;
        padding:25px;
    ">

        <h2 style="
            color:#b91c1c;
            margin-top:0;
        ">
            🚨 Autonomous Threat Alert
        </h2>

        <h3>
            {title}
        </h3>

        <table
            cellpadding="8"
            cellspacing="0"
            width="100%"
            style="border-collapse:collapse;"
        >

            <tr>
                <td>
                    <strong>Severity</strong>
                </td>
                <td>
                    {severity}
                </td>
            </tr>

            <tr>
                <td>
                    <strong>Threat Type</strong>
                </td>
                <td>
                    {threat_type}
                </td>
            </tr>

            <tr>
                <td>
                    <strong>Source IP</strong>
                </td>
                <td>
                    {source_ip}
                </td>
            </tr>

            <tr>
                <td>
                    <strong>Destination IP</strong>
                </td>
                <td>
                    {destination_ip}
                </td>
            </tr>

            <tr>
                <td>
                    <strong>Confidence</strong>
                </td>
                <td>
                    {confidence}
                </td>
            </tr>

            <tr>
                <td>
                    <strong>Detected By</strong>
                </td>
                <td>
                    {detection_source}
                </td>
            </tr>

            <tr>
                <td>
                    <strong>MITRE ATT&amp;CK</strong>
                </td>
                <td>
                    {mitre_techniques}
                </td>
            </tr>

        </table>

        <hr style="
            border:0;
            border-top:1px solid #e2e8f0;
            margin:25px 0;
        ">

        <p>
            <strong>Description:</strong>
        </p>

        <p>
            {description}
        </p>

        {evidence_block}

        <p>
            <strong>AI Analyst Summary:</strong>
        </p>

        <p>
            {llm_summary}
        </p>

        {recommendation_block}

        <hr style="
            border:0;
            border-top:1px solid #e2e8f0;
            margin:25px 0;
        ">

        <p style="
            font-size:12px;
            color:#64748b;
        ">
            This alert was generated automatically by the
            Autonomous Threat Hunting System.
        </p>

    </div>

</body>

</html>
"""


# ================================================================
# CREATE THREAT MESSAGE
# ================================================================

def _create_message(
    finding: dict,
    sender_email: str,
    recipient_email: str,
) -> EmailMessage:
    """
    Create HTML threat email.
    """

    severity = str(
        finding.get(
            "severity",
            "UNKNOWN",
        )
    ).strip().upper()

    title = str(
        finding.get(
            "title",
            "Threat Detected",
        )
    ).strip()

    if not title:
        title = "Threat Detected"

    message = EmailMessage()

    message["Subject"] = (
        f"[{severity}] {title}"
    )

    message["From"] = sender_email
    message["To"] = recipient_email

    html_body = _build_html_body(
        finding
    )

    message.set_content(
        "Autonomous Threat Alert. "
        "Please view this email in an HTML-capable email client."
    )

    message.add_alternative(
        html_body,
        subtype="html",
    )

    return message


# ================================================================
# GENERIC EMAIL
# ================================================================

def send_email(
    subject: str,
    body: str,
    to_email: Optional[str] = None,
    attachment_path: Optional[str] = None,
) -> bool:
    """
    Generic email sender.

    Used by registration OTP and other normal emails.

    Returns:
        True  = sent
        False = failed
    """

    enabled = _as_bool(
        _get_config(
            "EMAIL_ALERTS_ENABLED",
            True,
        ),
        True,
    )

    if not enabled:
        print(
            "Email alerts are disabled."
        )
        return False

    smtp_host = str(
        _get_config(
            "SMTP_HOST",
            "smtp.gmail.com",
        )
        or ""
    ).strip()

    smtp_port = _as_int(
        _get_config(
            "SMTP_PORT",
            587,
        ),
        587,
    )

    smtp_username = str(
        _get_config(
            "SMTP_USERNAME",
            "",
        )
        or ""
    ).strip()

    smtp_password = str(
        _get_config(
            "SMTP_PASSWORD",
            "",
        )
        or ""
    ).strip()

    sender_email = str(
        _get_config(
            "ALERT_EMAIL_FROM",
            "",
        )
        or ""
    ).strip()

    if not sender_email:
        sender_email = smtp_username

    receiver = _resolve_recipient_email(
        to_email
    )

    use_tls = _as_bool(
        _get_config(
            "SMTP_USE_TLS",
            True,
        ),
        True,
    )

    use_ssl = _as_bool(
        _get_config(
            "SMTP_USE_SSL",
            False,
        ),
        False,
    )

    timeout = _as_int(
        _get_config(
            "SMTP_TIMEOUT",
            30,
        ),
        30,
    )

    timeout = max(
        5,
        min(
            timeout,
            120,
        ),
    )

    # ------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------

    if not smtp_host:
        print(
            "SMTP_HOST is missing."
        )
        return False

    if not smtp_username:
        print(
            "SMTP_USERNAME is missing."
        )
        return False

    if not smtp_password:
        print(
            "SMTP_PASSWORD is missing."
        )
        return False

    if not sender_email:
        print(
            "ALERT_EMAIL_FROM is missing."
        )
        return False

    if not receiver:
        print(
            "Receiver email is missing."
        )
        return False

    if use_tls and use_ssl:
        print(
            "Invalid SMTP configuration: "
            "SMTP_USE_TLS and SMTP_USE_SSL "
            "cannot both be enabled."
        )
        return False

    # ------------------------------------------------------------
    # Create message
    # ------------------------------------------------------------

    message = EmailMessage()

    message["From"] = sender_email
    message["To"] = receiver
    message["Subject"] = subject

    message.set_content(
        str(body)
    )

    # ------------------------------------------------------------
    # Optional attachment
    # ------------------------------------------------------------

    if attachment_path:

        import os

        if os.path.exists(
            attachment_path
        ):

            try:

                with open(
                    attachment_path,
                    "rb",
                ) as file:

                    file_data = file.read()

                file_name = os.path.basename(
                    attachment_path
                )

                message.add_attachment(
                    file_data,
                    maintype="application",
                    subtype="pdf",
                    filename=file_name,
                )

            except Exception as exc:

                print(
                    f"Attachment error: {exc}"
                )

                return False

    # ------------------------------------------------------------
    # SMTP
    # ------------------------------------------------------------

    try:

        print(
            f"Connecting to "
            f"{smtp_host}:{smtp_port}..."
        )

        # ========================================================
        # SSL
        # ========================================================

        if use_ssl:

            with smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=timeout,
            ) as server:

                server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password,
                )

                server.send_message(
                    message
                )

        # ========================================================
        # Normal SMTP
        # ========================================================

        else:

            with smtplib.SMTP(
                smtp_host,
                smtp_port,
                timeout=timeout,
            ) as server:

                server.ehlo()

                if use_tls:

                    server.starttls()

                    server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password,
                )

                server.send_message(
                    message
                )

        print(
            f"Email successfully sent to "
            f"{receiver}"
        )

        return True

    except smtplib.SMTPAuthenticationError as exc:

        print(
            "SMTP authentication failed. "
            "Check SMTP_USERNAME and Gmail "
            "App Password."
        )

        print(
            f"SMTP details: {exc}"
        )

        return False

    except smtplib.SMTPRecipientsRefused as exc:

        print(
            f"SMTP rejected recipient: {exc}"
        )

        return False

    except smtplib.SMTPSenderRefused as exc:

        print(
            f"SMTP rejected sender: {exc}"
        )

        return False

    except smtplib.SMTPDataError as exc:

        print(
            f"SMTP data error: {exc}"
        )

        return False

    except smtplib.SMTPServerDisconnected as exc:

        print(
            f"SMTP server disconnected: {exc}"
        )

        return False

    except smtplib.SMTPConnectError as exc:

        print(
            f"Unable to connect to SMTP server: {exc}"
        )

        return False

    except TimeoutError as exc:

        print(
            f"SMTP connection timed out: {exc}"
        )

        return False

    except smtplib.SMTPException as exc:

        print(
            f"SMTP error: {exc}"
        )

        return False

    except Exception as exc:

        print(
            f"Email sending failed: {exc}"
        )

        return False


# ================================================================
# REGISTRATION OTP
# ================================================================

def send_registration_otp(
    user_email: str,
    otp: str,
) -> bool:
    """
    Send registration authorization OTP.
    """

    smtp_username = str(
        _get_config(
            "SMTP_USERNAME",
            "",
        )
        or ""
    ).strip()

    subject = (
        "Registration Authorization OTP"
    )

    body = f"""
Hello,

Your registration request has been authorized
by the administrator.

Admin Details:
Admin Name: System Administrator
Admin Email: {smtp_username}

Your Registration OTP:

{otp}

This OTP is valid for 10 minutes.

Use this OTP to complete your registration.

Regards,
Autonomous Threat Hunting System
"""

    return send_email(
        subject=subject,
        body=body,
        to_email=user_email,
    )


# ================================================================
# AUTONOMOUS THREAT ALERT
# ================================================================

def send_threat_alert_email(
    finding: dict,
    recipient_email: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Send an autonomous threat alert.

    Returns:

        ("SENT", None)

        ("SUPPRESSED", reason)

        ("FAILED", reason)
    """

    # ------------------------------------------------------------
    # 1. Validate finding
    # ------------------------------------------------------------

    if not isinstance(
        finding,
        dict,
    ):

        return (
            "FAILED",
            "Invalid threat finding supplied "
            "to email alert system.",
        )

    # ------------------------------------------------------------
    # 2. Severity
    # ------------------------------------------------------------

    severity = str(
        finding.get(
            "severity",
            "LOW",
        )
        or "LOW"
    ).strip().upper()

    # ------------------------------------------------------------
    # 3. Alert policy
    # ------------------------------------------------------------

    if not should_alert(
        severity
    ):

        if not _as_bool(
            _get_config(
                "EMAIL_ALERTS_ENABLED",
                False,
            ),
            False,
        ):

            return (
                "SUPPRESSED",
                "Email alerts are disabled "
                "in configuration.",
            )

        minimum = str(
            _get_config(
                "EMAIL_ALERT_MIN_SEVERITY",
                "MEDIUM",
            )
            or "MEDIUM"
        ).strip().upper()

        return (
            "SUPPRESSED",
            (
                f"Threat severity '{severity}' "
                f"is below the configured email "
                f"threshold '{minimum}'."
            ),
        )

    # ------------------------------------------------------------
    # 4. Resolve recipient
    # ------------------------------------------------------------

    resolved_recipient = (
        _resolve_recipient_email(
            recipient_email
        )
    )

    if not resolved_recipient:

        return (
            "FAILED",
            (
                "No recipient email is configured. "
                "Set ALERT_EMAIL_TO or "
                "LIVE_ALERT_RECIPIENT_EMAIL."
            ),
        )

    # ------------------------------------------------------------
    # 5. SMTP configuration
    # ------------------------------------------------------------

    smtp_host = str(
        _get_config(
            "SMTP_HOST",
            "",
        )
        or ""
    ).strip()

    if not smtp_host:

        return (
            "FAILED",
            "SMTP host is not configured.",
        )

    smtp_port = _as_int(
        _get_config(
            "SMTP_PORT",
            587,
        ),
        587,
    )

    if smtp_port <= 0:

        return (
            "FAILED",
            "SMTP port is invalid.",
        )

    smtp_username = str(
        _get_config(
            "SMTP_USERNAME",
            "",
        )
        or ""
    ).strip()

    if not smtp_username:

        return (
            "FAILED",
            "SMTP username is not configured.",
        )

    smtp_password = str(
        _get_config(
            "SMTP_PASSWORD",
            "",
        )
        or ""
    ).strip()

    if not smtp_password:

        return (
            "FAILED",
            "SMTP password/App Password is not configured.",
        )

    sender_email = str(
        _get_config(
            "ALERT_EMAIL_FROM",
            "",
        )
        or ""
    ).strip()

    if not sender_email:
        sender_email = smtp_username

    if not sender_email:

        return (
            "FAILED",
            "Alert sender email is not configured.",
        )

    # ------------------------------------------------------------
    # 6. SSL / TLS
    # ------------------------------------------------------------

    use_tls = _as_bool(
        _get_config(
            "SMTP_USE_TLS",
            True,
        ),
        True,
    )

    use_ssl = _as_bool(
        _get_config(
            "SMTP_USE_SSL",
            False,
        ),
        False,
    )

    if use_tls and use_ssl:

        return (
            "FAILED",
            (
                "Invalid SMTP configuration: "
                "SMTP_USE_TLS and SMTP_USE_SSL "
                "cannot both be enabled."
            ),
        )

    timeout = _as_int(
        _get_config(
            "SMTP_TIMEOUT",
            30,
        ),
        30,
    )

    timeout = max(
        5,
        min(
            timeout,
            120,
        ),
    )

    # ------------------------------------------------------------
    # 7. Build message
    # ------------------------------------------------------------

    try:

        message = _create_message(
            finding=finding,
            sender_email=sender_email,
            recipient_email=resolved_recipient,
        )

    except Exception as exc:

        return (
            "FAILED",
            f"Failed to build alert email: {exc}",
        )

    # ------------------------------------------------------------
    # 8. Send
    # ------------------------------------------------------------

    try:

        print(
            "================================================"
        )

        print(
            "AUTONOMOUS THREAT EMAIL"
        )

        print(
            f"Severity   : {severity}"
        )

        print(
            f"Recipient  : {resolved_recipient}"
        )

        print(
            f"SMTP       : {smtp_host}:{smtp_port}"
        )

        print(
            "================================================"
        )

        # ========================================================
        # SSL MODE
        # ========================================================

        if use_ssl:

            with smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=timeout,
            ) as server:

                server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password,
                )

                refused = server.sendmail(
                    sender_email,
                    [resolved_recipient],
                    message.as_string(),
                )

        # ========================================================
        # SMTP + STARTTLS
        # ========================================================

        else:

            with smtplib.SMTP(
                smtp_host,
                smtp_port,
                timeout=timeout,
            ) as server:

                server.ehlo()

                if use_tls:

                    server.starttls()

                    server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password,
                )

                refused = server.sendmail(
                    sender_email,
                    [resolved_recipient],
                    message.as_string(),
                )

        # --------------------------------------------------------
        # Recipient refused
        # --------------------------------------------------------

        if refused:

            rejected = ", ".join(
                str(address)
                for address in refused.keys()
            )

            return (
                "FAILED",
                f"SMTP rejected recipient(s): {rejected}",
            )

        print(
            f"Threat alert successfully sent to "
            f"{resolved_recipient}"
        )

        return (
            "SENT",
            None,
        )

    # ------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------

    except smtplib.SMTPAuthenticationError:

        return (
            "FAILED",
            (
                "SMTP authentication failed. "
                "Check SMTP_USERNAME and Gmail "
                "App Password."
            ),
        )

    # ------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------

    except smtplib.SMTPConnectError as exc:

        return (
            "FAILED",
            (
                "Unable to connect to SMTP server "
                f"{smtp_host}:{smtp_port}: {exc}"
            ),
        )

    # ------------------------------------------------------------
    # Timeout
    # ------------------------------------------------------------

    except TimeoutError:

        return (
            "FAILED",
            (
                "SMTP connection timed out while "
                f"connecting to {smtp_host}:{smtp_port}. "
                "Check Internet access, firewall, "
                "VPN, proxy, antivirus, and SMTP port."
            ),
        )

    # ------------------------------------------------------------
    # Recipient refused
    # ------------------------------------------------------------

    except smtplib.SMTPRecipientsRefused as exc:

        return (
            "FAILED",
            f"SMTP rejected recipient(s): {exc}",
        )

    # ------------------------------------------------------------
    # Sender refused
    # ------------------------------------------------------------

    except smtplib.SMTPSenderRefused as exc:

        return (
            "FAILED",
            f"SMTP rejected sender: {exc}",
        )

    # ------------------------------------------------------------
    # DATA error
    # ------------------------------------------------------------

    except smtplib.SMTPDataError as exc:

        return (
            "FAILED",
            f"SMTP data error: {exc}",
        )

    # ------------------------------------------------------------
    # Disconnected
    # ------------------------------------------------------------

    except smtplib.SMTPServerDisconnected as exc:

        return (
            "FAILED",
            f"SMTP server disconnected: {exc}",
        )

    # ------------------------------------------------------------
    # Other SMTP errors
    # ------------------------------------------------------------

    except smtplib.SMTPException as exc:

        return (
            "FAILED",
            f"SMTP error: {exc}",
        )

    # ------------------------------------------------------------
    # Unexpected error
    # ------------------------------------------------------------

    except Exception as exc:

        error_text = str(
            exc
        ).strip()

        if not error_text:
            error_text = (
                "Unknown SMTP error."
            )

        return (
            "FAILED",
            error_text,
        )


# ================================================================
# BACKWARD-COMPATIBILITY OBJECT
# ================================================================

class EmailAlert:
    """
    Compatibility class.

    Existing code can continue doing:

        email_alert = EmailAlert()

        email_alert.send_email(...)

        email_alert.send_registration_otp(...)

    while the actual SMTP implementation remains centralized.
    """

    def __init__(self):
        pass

    def send_email(
        self,
        subject,
        body,
        to_email=None,
        attachment_path=None,
    ):
        return send_email(
            subject=subject,
            body=body,
            to_email=to_email,
            attachment_path=attachment_path,
        )

    def send_registration_otp(
        self,
        user_email,
        otp,
    ):
        return send_registration_otp(
            user_email=user_email,
            otp=otp,
        )

    def send_threat_alert_email(
        self,
        finding,
        recipient_email=None,
    ):
        return send_threat_alert_email(
            finding=finding,
            recipient_email=recipient_email,
        )


# ================================================================
# GLOBAL EMAIL SERVICE
# ================================================================

email_alert = EmailAlert()


# ================================================================
# MODULE-LEVEL COMPATIBILITY FUNCTIONS
# ================================================================

def send_email_compat(
    subject,
    body,
    to_email=None,
    attachment_path=None,
):
    """
    Compatibility alias.
    """
    return send_email(
        subject=subject,
        body=body,
        to_email=to_email,
        attachment_path=attachment_path,
    )