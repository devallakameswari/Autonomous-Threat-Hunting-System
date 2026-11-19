
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
"""

import random
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
    session,
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
# GET CLIENT IP
# =========================================================

def get_client_ip():
    """
    Get client IP address.

    For normal local Flask development, request.remote_addr
    will be used.

    When deployed behind a trusted reverse proxy,
    X-Forwarded-For may contain the original client IP.
    """

    forwarded_ip = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_ip:

        client_ip = (
            forwarded_ip
            .split(",")[0]
            .strip()
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
    # GET REQUEST
    # -----------------------------------------------------

    if request.method == "GET":

        return render_template(
            "login.html"
        )

    # =====================================================
    # POST REQUEST
    # =====================================================

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
    # VALIDATE INPUT
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

    # -----------------------------------------------------
    # CLIENT IP
    # -----------------------------------------------------

    client_ip = get_client_ip()

    # =====================================================
    # SUCCESSFUL LOGIN
    # =====================================================

    if user and user.check_password(password):

        # Reset active failed-login counter
        user.failed_login_attempts = 0

        # Create login activity
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

        # Login user
        login_user(
            user,
            remember=remember
        )

        # Update last login
        user.last_login = datetime.utcnow()

        try:

            db.session.commit()

        except Exception as e:

            db.session.rollback()

            print(
                "Login database error:",
                e
            )

            flash(
                "Unable to complete login. Please try again.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # -------------------------------------------------
        # SAFE NEXT PAGE
        # -------------------------------------------------

        next_page = request.args.get("next")

        if (
            next_page
            and next_page.startswith("/")
            and not next_page.startswith("//")
        ):
            return redirect(next_page)

        return redirect(
            url_for("dashboard")
        )

    # =====================================================
    # FAILED LOGIN
    # =====================================================

    # -----------------------------------------------------
    # Detection window
    # -----------------------------------------------------

    detection_window_start = (
        datetime.utcnow()
        - timedelta(minutes=5)
    )

    # -----------------------------------------------------
    # Count recent failures for username + IP
    # -----------------------------------------------------

    recent_failed_attempts = (
        LoginActivity.query
        .filter(
            LoginActivity.username == username,
            LoginActivity.ip_address == client_ip,
            LoginActivity.login_status == "FAILED",
            LoginActivity.login_time >= detection_window_start
        )
        .count()
    )

    failed_attempt_count = (
        recent_failed_attempts + 1
    )

    # -----------------------------------------------------
    # UPDATE USER COUNTER
    # -----------------------------------------------------

    if user:

        user.failed_login_attempts = (
            failed_attempt_count
        )

    # =====================================================
    # DETERMINE THREAT
    # =====================================================

    if failed_attempt_count >= 10:

        threat_status = "BRUTE_FORCE"
        severity = "CRITICAL"

    elif failed_attempt_count >= 5:

        threat_status = "BRUTE_FORCE"
        severity = "HIGH"

    elif failed_attempt_count >= 3:

        threat_status = "SUSPICIOUS"
        severity = "MEDIUM"

    elif failed_attempt_count >= 2:

        threat_status = "SUSPICIOUS"
        severity = "LOW"

    else:

        threat_status = "NORMAL"
        severity = "LOW"

    # =====================================================
    # SAVE FAILED LOGIN
    # =====================================================

    login_activity = LoginActivity(
        username=username,

        user_id=(
            user.id
            if user
            else None
        ),

        ip_address=client_ip,

        login_status="FAILED",

        failed_attempts=failed_attempt_count,

        threat_status=threat_status,

        severity=severity,

        login_time=datetime.utcnow()
    )

    db.session.add(
        login_activity
    )

    try:

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        print(
            "Failed login database error:",
            e
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
            f"Failed Attempts : {failed_attempt_count}\n"
            f"Threat Status   : {threat_status}\n"
            f"Severity        : {severity}\n"
            "==================================================\n"
        )

    elif severity == "HIGH":

        print(
            "\n"
            "==================================================\n"
            "HIGH LOGIN THREAT\n"
            "==================================================\n"
            f"Username        : {username}\n"
            f"User ID         : "
            f"{user.id if user else 'UNKNOWN'}\n"
            f"IP Address      : {client_ip}\n"
            f"Failed Attempts : {failed_attempt_count}\n"
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
            f"Failed Attempts : {failed_attempt_count}\n"
            f"Severity        : {severity}\n"
            "==================================================\n"
        )

    # -----------------------------------------------------
    # USER MESSAGE
    # -----------------------------------------------------

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
    "/auth/register",
    methods=["GET"]
)
def register():

    return render_template(
        "login.html",
        show_register=True
    )


# =========================================================
# ADMIN: AUTHORIZE NEW USER
# =========================================================

@auth_bp.route(
    "/auth/authorize-user",
    methods=["POST"]
)
@login_required
def authorize_user():

    # -----------------------------------------------------
    # ADMIN ONLY
    # -----------------------------------------------------

    if current_user.role != "admin":

        return jsonify({
            "success": False,
            "message": (
                "Only admin can authorize users."
            )
        }), 403

    # -----------------------------------------------------
    # GET JSON DATA
    # -----------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()

    # -----------------------------------------------------
    # VALIDATE EMAIL
    # -----------------------------------------------------

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
    # CHECK REGISTERED USER
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
    # CHECK EXISTING AUTHORIZATION
    # -----------------------------------------------------

    existing_authorization = (
        AuthorizedUser.query
        .filter_by(
            email=email
        )
        .first()
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

    db.session.add(
        authorized_user
    )

    try:

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        print(
            "Authorization database error:",
            e
        )

        return jsonify({
            "success": False,
            "message": (
                "Unable to authorize this email."
            )
        }), 500

    # -----------------------------------------------------
    # SUCCESS
    # -----------------------------------------------------

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
    "/auth/authorized-users",
    methods=["GET"]
)
@login_required
def authorized_users():

    # -----------------------------------------------------
    # ADMIN ONLY
    # -----------------------------------------------------

    if current_user.role != "admin":

        return jsonify({
            "success": False,
            "message": (
                "Only admin can view authorized users."
            )
        }), 403

    # -----------------------------------------------------
    # GET USERS
    # -----------------------------------------------------

    users = (
        AuthorizedUser.query
        .order_by(
            AuthorizedUser.authorized_at.desc()
        )
        .all()
    )

    # -----------------------------------------------------
    # RETURN DATA
    # -----------------------------------------------------

    return jsonify({
        "success": True,
        "users": [
            {
                "id": user.id,

                "email": user.email,

                "used": bool(
                    user.used
                ),

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
    "/auth/send-registration-otp",
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

    # -----------------------------------------------------
    # VALIDATE EMAIL
    # -----------------------------------------------------

    if not email:

        return jsonify({
            "success": False,
            "message": "Email is required."
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
    # CHECK AUTHORIZATION
    # -----------------------------------------------------

    authorized_user = (
        AuthorizedUser.query
        .filter_by(
            email=email,
            used=False
        )
        .first()
    )

    if not authorized_user:

        return jsonify({
            "success": False,
            "message": (
                "This email is not authorized by admin. "
                "Please contact administrator."
            )
        }), 403

    # =====================================================
    # GENERATE OTP
    # =====================================================

    otp = str(
        random.randint(
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

    db.session.add(
        registration_otp
    )

    try:

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        print(
            "Registration OTP database error:",
            e
        )

        return jsonify({
            "success": False,
            "message": (
                "Unable to create registration OTP."
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

    except Exception as e:

        print(
            "Registration OTP email error:",
            e
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
    "/auth/verify-registration-otp",
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

    # -----------------------------------------------------
    # CHECK AUTHORIZATION
    # -----------------------------------------------------

    authorized_user = (
        AuthorizedUser.query
        .filter_by(
            email=email,
            used=False
        )
        .first()
    )

    if not authorized_user:

        return jsonify({
            "success": False,
            "message": (
                "Email is not authorized by admin."
            )
        }), 403

    # -----------------------------------------------------
    # FIND OTP
    # -----------------------------------------------------

    record = (
        RegistrationOTP.query
        .filter_by(
            email=email,
            otp=otp,
            used=False
        )
        .first()
    )

    if not record:

        return jsonify({
            "success": False,
            "message": "Invalid OTP."
        }), 400

    # -----------------------------------------------------
    # CHECK EXPIRATION
    # -----------------------------------------------------

    if (
        not record.expires_at
        or datetime.utcnow() > record.expires_at
    ):

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
    "/auth/complete-registration",
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

    # -----------------------------------------------------
    # VALIDATE
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # CHECK AUTHORIZATION
    # -----------------------------------------------------

    authorized_user = (
        AuthorizedUser.query
        .filter_by(
            email=email,
            used=False
        )
        .first()
    )

    if not authorized_user:

        return jsonify({
            "success": False,
            "message": (
                "Email is not authorized by admin."
            )
        }), 403

    # -----------------------------------------------------
    # CHECK OTP
    # -----------------------------------------------------

    record = (
        RegistrationOTP.query
        .filter_by(
            email=email,
            otp=otp,
            used=False
        )
        .first()
    )

    if not record:

        return jsonify({
            "success": False,
            "message": "Invalid OTP."
        }), 400

    # -----------------------------------------------------
    # CHECK EXPIRATION
    # -----------------------------------------------------

    if (
        not record.expires_at
        or datetime.utcnow() > record.expires_at
    ):

        return jsonify({
            "success": False,
            "message": "OTP expired."
        }), 400

    # -----------------------------------------------------
    # CHECK USERNAME
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # CHECK EMAIL
    # -----------------------------------------------------

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
        role="analyst",
        failed_login_attempts=0
    )

    user.set_password(
        password
    )

    db.session.add(
        user
    )

    # -----------------------------------------------------
    # MARK OTP USED
    # -----------------------------------------------------

    record.used = True

    # -----------------------------------------------------
    # MARK AUTHORIZATION USED
    # -----------------------------------------------------

    authorized_user.used = True

    try:

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        print(
            "Registration database error:",
            e
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
# ADMIN: LOGIN ACTIVITY
# =========================================================

@auth_bp.route(
    "/auth/admin/login-activity",
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
    "/auth/failed-logins",
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
    "/auth/ip-activity",
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
    "/auth/logout",
    methods=["GET", "POST"]
)
@login_required
def logout():

    # -----------------------------------------------------
    # LOGOUT FLASK-LOGIN USER
    # -----------------------------------------------------

    logout_user()

    # -----------------------------------------------------
    # CLEAR APPLICATION SESSION
    # -----------------------------------------------------

    session.clear()

    # -----------------------------------------------------
    # FLASH MESSAGE
    # -----------------------------------------------------

    flash(
        "You have been logged out successfully.",
        "info"
    )

    # -----------------------------------------------------
    # REDIRECT TO LOGIN
    # -----------------------------------------------------

    return redirect(
        url_for("auth.login")
    )
