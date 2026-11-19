
"""
Authentication/auth.py

Handles:
- Login
- Logout
- Registration
- Admin user authorization
- Registration OTP
- Admin login activity
- Admin IP activity
- Failed login tracking
- Brute-force detection
- Failed login details page
- Profile
- Logged-in user's own password change

PASSWORD POLICY
---------------
Password must:
- contain at least 8 characters
- contain at least one alphabet
- contain at least one number
- contain at least one special character
"""

import random
import re
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
)

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)

from Database.database import db

from Database.models import (
    User,
    RegistrationOTP,
    AuthorizedUser,
    LoginActivity,
)

from LLMs.email_alert import EmailAlert


# =========================================================
# BLUEPRINT
# =========================================================

auth_bp = Blueprint(
    "auth",
    __name__
)


# =========================================================
# LOGIN MANAGER
# =========================================================

login_manager = LoginManager()

login_manager.login_view = "auth.login"

login_manager.login_message = (
    "Please login to access this page."
)

login_manager.login_message_category = "warning"


def init_login_manager(app):
    """Initialize Flask-Login."""
    login_manager.init_app(app)


# =========================================================
# USER LOADER
# =========================================================

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None


# =========================================================
# PASSWORD VALIDATION
# =========================================================

def is_strong_password(password):
    """
    Validate the application's password policy.

    Requirements:
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
    """Return the standard password policy message."""
    return (
        "Password must be at least 8 characters and contain "
        "at least one alphabet, one number, and one special character."
    )


# =========================================================
# GET CLIENT IP
# =========================================================

def get_client_ip():
    """Get the client IP address safely."""

    forwarded_ip = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_ip:
        client_ip = (
            forwarded_ip.split(",")[0].strip()
        )
    else:
        client_ip = request.remote_addr

    if not client_ip:
        client_ip = "UNKNOWN"

    return client_ip


# =========================================================
# LOGIN
# =========================================================

@auth_bp.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    # -----------------------------------------------------
    # ALREADY LOGGED IN
    # -----------------------------------------------------

    if current_user.is_authenticated:
        return redirect(
            url_for("dashboard")
        )

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    if request.method == "GET":
        return render_template(
            "login.html"
        )

    # -----------------------------------------------------
    # POST
    # -----------------------------------------------------

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    remember = bool(
        request.form.get("remember")
    )

    # -----------------------------------------------------
    # VALIDATE
    # -----------------------------------------------------

    if not username or not password:
        flash(
            "Username and password are required.",
            "danger"
        )

        return render_template(
            "login.html"
        )

    # -----------------------------------------------------
    # FIND USER
    # -----------------------------------------------------

    user = User.query.filter_by(
        username=username
    ).first()

    client_ip = get_client_ip()

    # =====================================================
    # SUCCESSFUL LOGIN
    # =====================================================

    if user and user.check_password(password):

        activity = LoginActivity(
            username=username,
            user_id=user.id,
            ip_address=client_ip,
            login_status="SUCCESS",
            failed_attempts=0,
            threat_status="NORMAL",
            severity="LOW",
            login_time=datetime.utcnow()
        )

        db.session.add(activity)

        # Login
        login_user(
            user,
            remember=remember
        )

        # Update last login
        user.last_login = datetime.utcnow()

        try:
            db.session.commit()

        except Exception as exc:
            db.session.rollback()

            print(
                "Successful login database error:",
                exc
            )

        # -------------------------------------------------
        # SAFE NEXT URL
        # -------------------------------------------------

        next_page = request.args.get("next")

        if (
            not next_page
            or not next_page.startswith("/")
            or next_page.startswith("//")
        ):
            next_page = url_for("dashboard")

        return redirect(next_page)

    # =====================================================
    # FAILED LOGIN
    # =====================================================

    previous_failed_attempts = (
        LoginActivity.query
        .filter(
            LoginActivity.username == username,
            LoginActivity.login_status == "FAILED"
        )
        .count()
    )

    failed_login_count = (
        previous_failed_attempts + 1
    )

    # =====================================================
    # THREAT LEVEL
    # =====================================================

    if failed_login_count >= 10:

        threat_status = "BRUTE_FORCE"
        severity = "CRITICAL"

    elif failed_login_count >= 5:

        threat_status = "BRUTE_FORCE"
        severity = "HIGH"

    elif failed_login_count >= 3:

        threat_status = "SUSPICIOUS"
        severity = "MEDIUM"

    else:

        threat_status = "NORMAL"
        severity = "LOW"

    # =====================================================
    # SAVE FAILED LOGIN
    # =====================================================

    login_activity = LoginActivity(
        username=username,
        user_id=user.id if user else None,
        ip_address=client_ip,
        login_status="FAILED",
        failed_attempts=failed_login_count,
        threat_status=threat_status,
        severity=severity,
        login_time=datetime.utcnow()
    )

    db.session.add(login_activity)

    try:
        db.session.commit()

    except Exception as exc:
        db.session.rollback()

        print(
            "Failed login database error:",
            exc
        )

    # =====================================================
    # SECURITY CONSOLE ALERT
    # =====================================================

    if threat_status == "BRUTE_FORCE":

        print(
            "\n"
            "==================================================\n"
            "BRUTE FORCE ATTACK DETECTED\n"
            "==================================================\n"
            f"Username        : {username}\n"
            f"User ID         : "
            f"{user.id if user else 'UNKNOWN'}\n"
            f"IP Address      : {client_ip}\n"
            f"Failed Attempts : {failed_login_count}\n"
            f"Threat Status   : {threat_status}\n"
            f"Severity        : {severity}\n"
            "==================================================\n"
        )

    elif severity == "MEDIUM":

        print(
            "\n"
            "==================================================\n"
            "SUSPICIOUS LOGIN ATTEMPT\n"
            "==================================================\n"
            f"Username        : {username}\n"
            f"User ID         : "
            f"{user.id if user else 'UNKNOWN'}\n"
            f"IP Address      : {client_ip}\n"
            f"Failed Attempts : {failed_login_count}\n"
            f"Severity        : {severity}\n"
            "==================================================\n"
        )

    flash(
        "Invalid username or password.",
        "danger"
    )

    return render_template(
        "login.html",
        show_register=False
    )


# =========================================================
# REGISTER PAGE
# =========================================================

@auth_bp.route(
    "/register",
    methods=["GET"]
)
def register():

    return render_template(
        "login.html",
        show_register=True
    )


# =========================================================
# ADMIN: AUTHORIZE USER
# =========================================================

@auth_bp.route(
    "/authorize-user",
    methods=["POST"]
)
@login_required
def authorize_user():

    if current_user.role != "admin":

        return jsonify({
            "success": False,
            "message": (
                "Only admin can authorize users."
            )
        }), 403

    data = request.get_json(
        silent=True
    ) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()

    if not email:

        return jsonify({
            "success": False,
            "message": "Email is required."
        }), 400

    if (
        "@" not in email
        or "." not in email.split("@")[-1]
    ):

        return jsonify({
            "success": False,
            "message": (
                "Please enter a valid email address."
            )
        }), 400

    # -----------------------------------------------------
    # EXISTING USER
    # -----------------------------------------------------

    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:

        return jsonify({
            "success": False,
            "message": (
                "This email is already registered."
            )
        }), 400

    # -----------------------------------------------------
    # EXISTING AUTHORIZATION
    # -----------------------------------------------------

    existing_authorization = (
        AuthorizedUser.query.filter_by(
            email=email
        ).first()
    )

    if existing_authorization:

        if existing_authorization.used:

            return jsonify({
                "success": False,
                "message": (
                    "This email has already been used "
                    "for registration."
                )
            }), 400

        return jsonify({
            "success": False,
            "message": (
                "This email is already authorized."
            )
        }), 400

    # -----------------------------------------------------
    # CREATE AUTHORIZATION
    # -----------------------------------------------------

    authorized_user = AuthorizedUser(
        email=email,
        authorized_by=current_user.id,
        authorized_at=datetime.utcnow(),
        used=False
    )

    db.session.add(authorized_user)

    try:
        db.session.commit()

    except Exception as exc:

        db.session.rollback()

        print(
            "Authorization database error:",
            exc
        )

        return jsonify({
            "success": False,
            "message": (
                "Unable to authorize this email."
            )
        }), 500

    return jsonify({
        "success": True,
        "message": (
            f"Successfully! New user {email} "
            f"has been authorized."
        ),
        "email": email,
        "authorized_by": current_user.username,
        "authorized_at": (
            authorized_user.authorized_at.isoformat()
            if authorized_user.authorized_at
            else None
        )
    }), 201


# =========================================================
# ADMIN: AUTHORIZED USERS
# =========================================================

@auth_bp.route(
    "/authorized-users",
    methods=["GET"]
)
@login_required
def authorized_users():

    if current_user.role != "admin":

        return jsonify({
            "success": False,
            "message": (
                "Only admin can view "
                "authorized users."
            )
        }), 403

    users = (
        AuthorizedUser.query
        .order_by(
            AuthorizedUser.authorized_at.desc()
        )
        .all()
    )

    return jsonify({
        "success": True,
        "users": [
            {
                "id": user.id,
                "email": user.email,
                "used": bool(user.used),
                "authorized_by": (
                    user.admin.username
                    if user.admin
                    else "Admin"
                ),
                "authorized_at": (
                    user.authorized_at.isoformat()
                    if user.authorized_at
                    else None
                )
            }
            for user in users
        ]
    }), 200


# =========================================================
# SEND REGISTRATION OTP
# =========================================================

@auth_bp.route(
    "/send-registration-otp",
    methods=["POST"]
)
def send_registration_otp():

    data = request.get_json(
        silent=True
    ) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()

    if not email:

        return jsonify({
            "success": False,
            "message": "Email is required."
        }), 400

    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:

        return jsonify({
            "success": False,
            "message": (
                "This email is already registered."
            )
        }), 400

    authorized_user = (
        AuthorizedUser.query.filter_by(
            email=email,
            used=False
        ).first()
    )

    if not authorized_user:

        return jsonify({
            "success": False,
            "message": (
                "This email is not authorized by admin. "
                "Please contact administrator."
            )
        }), 403

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
    # DELETE OLD OTP
    # -----------------------------------------------------

    RegistrationOTP.query.filter_by(
        email=email,
        used=False
    ).delete()

    # -----------------------------------------------------
    # CREATE OTP
    # -----------------------------------------------------

    registration_otp = RegistrationOTP(
        email=email,
        otp=otp,
        expires_at=expires_at,
        used=False,
        admin_id=authorized_user.authorized_by
    )

    db.session.add(registration_otp)

    try:
        db.session.commit()

    except Exception as exc:

        db.session.rollback()

        print(
            "OTP database error:",
            exc
        )

        return jsonify({
            "success": False,
            "message": (
                "Unable to generate OTP."
            )
        }), 500

    # -----------------------------------------------------
    # SEND EMAIL
    # -----------------------------------------------------

    email_alert = EmailAlert()

    try:

        sent = email_alert.send_registration_otp(
            email,
            otp
        )

    except Exception as exc:

        print(
            "Registration OTP email error:",
            exc
        )

        sent = False

    if not sent:

        return jsonify({
            "success": False,
            "message": (
                "Unable to send OTP email. "
                "Please try again."
            )
        }), 500

    return jsonify({
        "success": True,
        "message": (
            "OTP sent successfully "
            "to your email."
        )
    }), 200


# =========================================================
# VERIFY REGISTRATION OTP
# =========================================================

@auth_bp.route(
    "/verify-registration-otp",
    methods=["POST"]
)
def verify_registration_otp():

    data = request.get_json(
        silent=True
    ) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()

    otp = str(
        data.get(
            "otp",
            ""
        )
    ).strip()

    if not email or not otp:

        return jsonify({
            "success": False,
            "message": (
                "Email and OTP are required."
            )
        }), 400

    authorized_user = (
        AuthorizedUser.query.filter_by(
            email=email,
            used=False
        ).first()
    )

    if not authorized_user:

        return jsonify({
            "success": False,
            "message": (
                "Email is not authorized by admin."
            )
        }), 403

    record = RegistrationOTP.query.filter_by(
        email=email,
        otp=otp,
        used=False
    ).first()

    if not record:

        return jsonify({
            "success": False,
            "message": "Invalid OTP."
        }), 400

    if datetime.utcnow() > record.expires_at:

        return jsonify({
            "success": False,
            "message": "OTP expired."
        }), 400

    return jsonify({
        "success": True,
        "message": (
            "OTP verified successfully."
        )
    }), 200


# =========================================================
# COMPLETE REGISTRATION
# =========================================================

@auth_bp.route(
    "/complete-registration",
    methods=["POST"]
)
def complete_registration():

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get(
        "username",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    otp = str(
        data.get(
            "otp",
            ""
        )
    ).strip()

    if (
        not username
        or not email
        or not password
        or not otp
    ):

        return jsonify({
            "success": False,
            "message": (
                "All fields are required."
            )
        }), 400

    # =====================================================
    # PASSWORD POLICY
    # =====================================================

    if not is_strong_password(password):

        return jsonify({
            "success": False,
            "message": password_policy_message()
        }), 400

    # =====================================================
    # AUTHORIZATION CHECK
    # =====================================================

    authorized_user = (
        AuthorizedUser.query.filter_by(
            email=email,
            used=False
        ).first()
    )

    if not authorized_user:

        return jsonify({
            "success": False,
            "message": (
                "Email is not authorized by admin."
            )
        }), 403

    # =====================================================
    # OTP CHECK
    # =====================================================

    record = RegistrationOTP.query.filter_by(
        email=email,
        otp=otp,
        used=False
    ).first()

    if not record:

        return jsonify({
            "success": False,
            "message": "Invalid OTP."
        }), 400

    if datetime.utcnow() > record.expires_at:

        return jsonify({
            "success": False,
            "message": "OTP expired."
        }), 400

    # =====================================================
    # USERNAME CHECK
    # =====================================================

    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username:

        return jsonify({
            "success": False,
            "message": (
                "Username already exists."
            )
        }), 400

    # =====================================================
    # EMAIL CHECK
    # =====================================================

    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email:

        return jsonify({
            "success": False,
            "message": (
                "Email already registered."
            )
        }), 400

    # =====================================================
    # CREATE USER
    # =====================================================

    user = User(
        username=username,
        email=email,
        role="analyst"
    )

    user.set_password(password)

    db.session.add(user)

    # =====================================================
    # MARK OTP USED
    # =====================================================

    record.used = True

    # =====================================================
    # MARK AUTHORIZATION USED
    # =====================================================

    authorized_user.used = True

    try:

        db.session.commit()

    except Exception as exc:

        db.session.rollback()

        print(
            "Registration database error:",
            exc
        )

        return jsonify({
            "success": False,
            "message": (
                "Unable to complete registration."
            )
        }), 500

    return jsonify({
        "success": True,
        "message": (
            "Registration successful. "
            "You can now login."
        )
    }), 201


# =========================================================
# PROFILE
# =========================================================

@auth_bp.route(
    "/profile",
    methods=["GET", "POST"]
)
@login_required
def profile():

    # -----------------------------------------------------
    # GET PROFILE
    # -----------------------------------------------------

    if request.method == "GET":

        return render_template(
            "profile.html",
            user=current_user
        )

    # =====================================================
    # PASSWORD CHANGE
    # =====================================================

    current_password = request.form.get(
        "current_password",
        ""
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    # -----------------------------------------------------
    # REQUIRED FIELDS
    # -----------------------------------------------------

    if not current_password:

        flash(
            "Current password is required.",
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
        )

    if not new_password:

        flash(
            "New password is required.",
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
        )

    if not confirm_password:

        flash(
            "Please confirm your new password.",
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
        )

    # -----------------------------------------------------
    # CURRENT PASSWORD
    # -----------------------------------------------------

    if not current_user.check_password(
        current_password
    ):

        flash(
            "Current password is incorrect.",
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
        )

    # -----------------------------------------------------
    # NEW PASSWORD POLICY
    # -----------------------------------------------------

    if not is_strong_password(
        new_password
    ):

        flash(
            password_policy_message(),
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
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
            "profile.html",
            user=current_user
        )

    # -----------------------------------------------------
    # PREVENT SAME PASSWORD
    # -----------------------------------------------------

    if current_user.check_password(
        new_password
    ):

        flash(
            "New password must be different from your current password.",
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
        )

    # -----------------------------------------------------
    # UPDATE PASSWORD
    # -----------------------------------------------------

    try:

        current_user.set_password(
            new_password
        )

        db.session.commit()

        flash(
            "Your password has been changed successfully.",
            "success"
        )

        return redirect(
            url_for("auth.profile")
        )

    except Exception as exc:

        db.session.rollback()

        print(
            "Password change database error:",
            exc
        )

        flash(
            "Unable to change password. Please try again.",
            "danger"
        )

        return render_template(
            "profile.html",
            user=current_user
        )


# =========================================================
# ADMIN: LOGIN ACTIVITY
# =========================================================

@auth_bp.route(
    "/admin/login-activity",
    methods=["GET"]
)
@login_required
def admin_login_activity():

    if current_user.role != "admin":

        return jsonify({
            "success": False,
            "message": (
                "Only admin can access "
                "login activity."
            )
        }), 403

    activities = (
        LoginActivity.query
        .order_by(
            LoginActivity.login_time.desc()
        )
        .limit(100)
        .all()
    )

    return jsonify({
        "success": True,
        "activities": [
            activity.to_dict()
            for activity in activities
        ]
    }), 200


# =========================================================
# ADMIN: FAILED LOGIN DETAILS
# =========================================================

@auth_bp.route(
    "/failed-logins",
    methods=["GET"]
)
@login_required
def failed_logins():

    if current_user.role != "admin":

        flash(
            "Only admin can view failed login attempts.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    failed_login_records = (
        LoginActivity.query
        .filter(
            LoginActivity.login_status == "FAILED"
        )
        .order_by(
            LoginActivity.login_time.desc()
        )
        .all()
    )

    return render_template(
        "failed_logins.html",
        failed_logins=failed_login_records
    )


# =========================================================
# ADMIN: IP ACTIVITY
# =========================================================

@auth_bp.route(
    "/admin/ip-activity",
    methods=["GET"]
)
@login_required
def admin_ip_activity():

    if current_user.role != "admin":

        return jsonify({
            "success": False,
            "message": (
                "Only admin can access "
                "IP activity."
            )
        }), 403

    activities = (
        LoginActivity.query
        .order_by(
            LoginActivity.login_time.desc()
        )
        .limit(100)
        .all()
    )

    return jsonify({
        "success": True,
        "activities": [
            activity.to_dict()
            for activity in activities
        ]
    }), 200


# =========================================================
# LOGOUT
# =========================================================

@auth_bp.route(
    "/logout",
    methods=["GET", "POST"]
)
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out successfully.",
        "info"
    )

    return redirect(
        url_for("auth.login")
    )
