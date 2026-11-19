
"""
Authentication/forgot_password.py

Forgot Password / Password Reset

Flow:
1. User enters registered email.
2. System generates a 6-digit OTP.
3. OTP is emailed to the registered email.
4. OTP is valid for 10 minutes.
5. User verifies OTP.
6. User enters a new strong password.
7. Password is changed for that account.

PASSWORD POLICY
---------------
- Minimum 8 characters
- At least one alphabet
- At least one number
- At least one special character
"""

import random
import re
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from Database.database import db
from Database.models import User

from config import Config


# =========================================================
# BLUEPRINT
# =========================================================

forgot_password_bp = Blueprint(
    "forgot_password",
    __name__,
    url_prefix="/forgot-password"
)


# =========================================================
# TEMPORARY OTP STORE
# =========================================================
#
# Used for OTP verification during local development.
#
# Structure:
#
# otp_store[email] = {
#     "otp": "123456",
#     "expires": datetime,
#     "verified": False,
#     "user_id": 1
# }
#
# =========================================================

otp_store = {}


# =========================================================
# PASSWORD VALIDATION
# =========================================================

def is_strong_password(password):
    """
    Password must contain:

    - Minimum 8 characters
    - At least one alphabet
    - At least one number
    - At least one special character
    """

    if not isinstance(password, str):
        return False

    if len(password) < 8:
        return False

    if not re.search(r"[A-Za-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    if not re.search(r"[^A-Za-z0-9]", password):
        return False

    return True


def password_policy_message():
    return (
        "Password must be at least 8 characters and contain "
        "at least one alphabet, one number, and one special character."
    )


# =========================================================
# SEND OTP EMAIL
# =========================================================

def send_password_reset_otp_email(
    recipient_email,
    username,
    otp
):
    """
    Send password-reset OTP using the project's SMTP
    configuration.
    """

    smtp_host = getattr(
        Config,
        "SMTP_HOST",
        ""
    )

    smtp_port = getattr(
        Config,
        "SMTP_PORT",
        587
    )

    smtp_username = getattr(
        Config,
        "SMTP_USERNAME",
        ""
    )

    smtp_password = getattr(
        Config,
        "SMTP_PASSWORD",
        ""
    )

    smtp_use_tls = getattr(
        Config,
        "SMTP_USE_TLS",
        True
    )

    smtp_use_ssl = getattr(
        Config,
        "SMTP_USE_SSL",
        False
    )

    sender_email = getattr(
        Config,
        "ALERT_EMAIL_FROM",
        ""
    ) or smtp_username

    smtp_timeout = getattr(
        Config,
        "SMTP_TIMEOUT",
        15
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not smtp_host:

        print(
            "Password reset email error: "
            "SMTP_HOST is not configured."
        )

        return False

    if not smtp_port:

        print(
            "Password reset email error: "
            "SMTP_PORT is not configured."
        )

        return False

    if not smtp_username:

        print(
            "Password reset email error: "
            "SMTP_USERNAME is not configured."
        )

        return False

    if not smtp_password:

        print(
            "Password reset email error: "
            "SMTP_PASSWORD is not configured."
        )

        return False

    if not sender_email:

        print(
            "Password reset email error: "
            "ALERT_EMAIL_FROM is not configured."
        )

        return False

    # -----------------------------------------------------
    # CREATE EMAIL
    # -----------------------------------------------------

    message = EmailMessage()

    message["Subject"] = (
        "Password Reset OTP - "
        "Autonomous Threat Hunting System"
    )

    message["From"] = sender_email

    message["To"] = recipient_email

    message.set_content(
        f"""
Hello {username},

We received a request to reset your password
for the Autonomous Threat Hunting System.

Your password reset OTP is:

{otp}

This OTP is valid for 10 minutes.

If you did not request a password reset,
please ignore this email.

Autonomous Threat Hunting System
"""
    )

    try:

        # =================================================
        # SSL MODE
        # =================================================

        if smtp_use_ssl:

            with smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=smtp_timeout
            ) as server:

                server.login(
                    smtp_username,
                    smtp_password
                )

                server.send_message(
                    message
                )

        # =================================================
        # NORMAL SMTP / TLS MODE
        # =================================================

        else:

            with smtplib.SMTP(
                smtp_host,
                smtp_port,
                timeout=smtp_timeout
            ) as server:

                server.ehlo()

                if smtp_use_tls:

                    server.starttls()

                    server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password
                )

                server.send_message(
                    message
                )

        print(
            f"Password reset OTP email sent to "
            f"{recipient_email}"
        )

        return True

    except smtplib.SMTPAuthenticationError:

        print(
            "Password reset email error: "
            "SMTP authentication failed. "
            "Check SMTP username and App Password."
        )

        return False

    except smtplib.SMTPConnectError as exc:

        print(
            "Password reset email connection error:",
            exc
        )

        return False

    except smtplib.SMTPRecipientsRefused as exc:

        print(
            "Password reset recipient rejected:",
            exc
        )

        return False

    except smtplib.SMTPException as exc:

        print(
            "Password reset SMTP error:",
            exc
        )

        return False

    except Exception as exc:

        print(
            "Password reset email unexpected error:",
            exc
        )

        return False


# =========================================================
# FORGOT PASSWORD
# =========================================================

@forgot_password_bp.route(
    "/",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "GET":

        return render_template(
            "forgot_password.html"
        )

    # -----------------------------------------------------
    # GET EMAIL
    # -----------------------------------------------------

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    if not email:

        flash(
            "Please enter your email address.",
            "danger"
        )

        return render_template(
            "forgot_password.html"
        )

    # -----------------------------------------------------
    # FIND USER
    # -----------------------------------------------------

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        flash(
            "No account found with this email address.",
            "danger"
        )

        return render_template(
            "forgot_password.html"
        )

    # -----------------------------------------------------
    # GENERATE OTP
    # -----------------------------------------------------

    otp = str(
        random.SystemRandom().randint(
            100000,
            999999
        )
    )

    expires_at = (
        datetime.utcnow()
        + timedelta(minutes=10)
    )

    # -----------------------------------------------------
    # STORE OTP
    # -----------------------------------------------------

    otp_store[email] = {
        "otp": otp,
        "expires": expires_at,
        "verified": False,
        "user_id": user.id
    }

    # -----------------------------------------------------
    # SEND EMAIL
    # -----------------------------------------------------

    sent = send_password_reset_otp_email(
        recipient_email=email,
        username=user.username,
        otp=otp
    )

    if not sent:

        otp_store.pop(
            email,
            None
        )

        flash(
            "Unable to send OTP email. "
            "Please check your email configuration and try again.",
            "danger"
        )

        return render_template(
            "forgot_password.html"
        )

    flash(
        "OTP sent to your registered email address.",
        "success"
    )

    return redirect(
        url_for(
            "forgot_password.verify_otp",
            email=email
        )
    )


# =========================================================
# VERIFY OTP
# =========================================================

@forgot_password_bp.route(
    "/verify",
    methods=["GET", "POST"]
)
def verify_otp():

    email = request.args.get(
        "email",
        ""
    ).strip().lower()

    # -----------------------------------------------------
    # ALSO ACCEPT POST EMAIL
    # -----------------------------------------------------

    if request.method == "POST":

        posted_email = request.form.get(
            "email",
            ""
        ).strip().lower()

        if posted_email:

            email = posted_email

    if not email:

        flash(
            "Email address is required.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    if request.method == "GET":

        return render_template(
            "verify_otp.html",
            email=email
        )

    # -----------------------------------------------------
    # OTP
    # -----------------------------------------------------

    otp = request.form.get(
        "otp",
        ""
    ).strip()

    if not otp:

        flash(
            "Please enter the OTP.",
            "danger"
        )

        return render_template(
            "verify_otp.html",
            email=email
        )

    record = otp_store.get(
        email
    )

    if not record:

        flash(
            "OTP not found. Please request a new OTP.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    # -----------------------------------------------------
    # EXPIRATION
    # -----------------------------------------------------

    if datetime.utcnow() > record["expires"]:

        otp_store.pop(
            email,
            None
        )

        flash(
            "OTP expired. Please request a new OTP.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    # -----------------------------------------------------
    # VERIFY
    # -----------------------------------------------------

    if str(record["otp"]) != str(otp):

        flash(
            "Invalid OTP.",
            "danger"
        )

        return render_template(
            "verify_otp.html",
            email=email
        )

    # -----------------------------------------------------
    # MARK VERIFIED
    # -----------------------------------------------------

    record["verified"] = True

    return redirect(
        url_for(
            "forgot_password.reset_password",
            email=email
        )
    )


# =========================================================
# RESET PASSWORD
# =========================================================

@forgot_password_bp.route(
    "/reset",
    methods=["GET", "POST"]
)
def reset_password():

    email = request.args.get(
        "email",
        ""
    ).strip().lower()

    if not email:

        flash(
            "Email address is required.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    record = otp_store.get(
        email
    )

    if not record:

        flash(
            "Password reset session expired. "
            "Please request a new OTP.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    # -----------------------------------------------------
    # EXPIRATION
    # -----------------------------------------------------

    if datetime.utcnow() > record["expires"]:

        otp_store.pop(
            email,
            None
        )

        flash(
            "OTP expired. Please request a new OTP.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    # -----------------------------------------------------
    # OTP MUST BE VERIFIED
    # -----------------------------------------------------

    if not record.get(
        "verified",
        False
    ):

        flash(
            "Please verify your OTP first.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.verify_otp",
                email=email
            )
        )

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    if request.method == "GET":

        return render_template(
            "reset_password.html",
            email=email
        )

    # -----------------------------------------------------
    # POST
    # -----------------------------------------------------

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    # -----------------------------------------------------
    # REQUIRED
    # -----------------------------------------------------

    if not new_password:

        flash(
            "New password is required.",
            "danger"
        )

        return render_template(
            "reset_password.html",
            email=email
        )

    if not confirm_password:

        flash(
            "Please confirm your new password.",
            "danger"
        )

        return render_template(
            "reset_password.html",
            email=email
        )

    # -----------------------------------------------------
    # PASSWORD POLICY
    # -----------------------------------------------------

    if not is_strong_password(
        new_password
    ):

        flash(
            password_policy_message(),
            "danger"
        )

        return render_template(
            "reset_password.html",
            email=email
        )

    # -----------------------------------------------------
    # CONFIRM PASSWORD
    # -----------------------------------------------------

    if new_password != confirm_password:

        flash(
            "New password and confirm password do not match.",
            "danger"
        )

        return render_template(
            "reset_password.html",
            email=email
        )

    # -----------------------------------------------------
    # FIND USER
    # -----------------------------------------------------

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        otp_store.pop(
            email,
            None
        )

        flash(
            "User account was not found.",
            "danger"
        )

        return redirect(
            url_for(
                "forgot_password.forgot_password"
            )
        )

    # -----------------------------------------------------
    # PREVENT SAME PASSWORD
    # -----------------------------------------------------

    if user.check_password(
        new_password
    ):

        flash(
            "New password must be different from your current password.",
            "danger"
        )

        return render_template(
            "reset_password.html",
            email=email
        )

    # -----------------------------------------------------
    # UPDATE PASSWORD
    # -----------------------------------------------------

    try:

        user.set_password(
            new_password
        )

        db.session.commit()

    except Exception as exc:

        db.session.rollback()

        print(
            "Password reset database error:",
            exc
        )

        flash(
            "Unable to reset password. Please try again.",
            "danger"
        )

        return render_template(
            "reset_password.html",
            email=email
        )

    # -----------------------------------------------------
    # DELETE USED OTP
    # -----------------------------------------------------

    otp_store.pop(
        email,
        None
    )

    flash(
        "Password reset successfully. You can now login.",
        "success"
    )

    return redirect(
        url_for(
            "auth.login"
        )
    )
