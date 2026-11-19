import random
from datetime import datetime, timedelta

from flask import request, jsonify
from flask_login import current_user, login_required

from Database.database import db
from Database.models import User, RegistrationOTP, AuthorizedUser
from LLMs.email_alert import EmailAlert


def generate_otp():
    return str(random.randint(100000, 999999))


# =========================================================
# ADMIN: AUTHORIZE NEW USER EMAIL
# =========================================================

@login_required
def authorize_user():
    """
    Admin adds/authorizes a new user's email.
    """

    if current_user.role != "admin":
        return jsonify({
            "success": False,
            "message": "Only admin can authorize users"
        }), 403

    data = request.get_json() or {}

    email = data.get("email")

    if not email:
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    email = email.strip().lower()

    # Check existing user
    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:
        return jsonify({
            "success": False,
            "message": "User already registered"
        }), 400

    # Check already authorized
    existing_authorized = AuthorizedUser.query.filter_by(
        email=email
    ).first()

    if existing_authorized:
        return jsonify({
            "success": False,
            "message": "Email is already authorized"
        }), 400

    authorized_user = AuthorizedUser(
        email=email,
        authorized_by=current_user.id,
        used=False
    )

    db.session.add(authorized_user)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "User email authorized successfully"
    }), 201


# =========================================================
# USER: CHECK EMAIL AND SEND OTP
# =========================================================

def send_registration_otp():

    data = request.get_json() or {}

    email = data.get("email")

    if not email:
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    email = email.strip().lower()

    # Check whether already registered
    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:
        return jsonify({
            "success": False,
            "message": "This email is already registered"
        }), 400

    # Check ADMIN authorization
    authorized_user = AuthorizedUser.query.filter_by(
        email=email,
        used=False
    ).first()

    if not authorized_user:
        return jsonify({
            "success": False,
            "message": (
                "This email is not authorized by admin. "
                "Please contact administrator."
            )
        }), 403

    # Generate OTP
    otp = generate_otp()

    expires_at = datetime.utcnow() + timedelta(
        minutes=10
    )

    # Delete old OTP
    RegistrationOTP.query.filter_by(
        email=email,
        used=False
    ).delete()

    # Save new OTP
    registration_otp = RegistrationOTP(
        email=email,
        otp=otp,
        admin_id=authorized_user.authorized_by,
        expires_at=expires_at,
        used=False
    )

    db.session.add(registration_otp)
    db.session.commit()

    # Send OTP
    email_alert = EmailAlert()

    if not email_alert.send_registration_otp(
        email,
        otp
    ):
        return jsonify({
            "success": False,
            "message": "Unable to send OTP email"
        }), 500

    return jsonify({
        "success": True,
        "message": "OTP sent successfully to your email"
    }), 200


# =========================================================
# USER: VERIFY OTP
# =========================================================

def verify_registration_otp():

    data = request.get_json() or {}

    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({
            "success": False,
            "message": "Email and OTP are required"
        }), 400

    email = email.strip().lower()
    otp = str(otp).strip()

    record = RegistrationOTP.query.filter_by(
        email=email,
        otp=otp,
        used=False
    ).first()

    if not record:
        return jsonify({
            "success": False,
            "message": "Invalid OTP"
        }), 400

    # Check expiry
    if datetime.utcnow() > record.expires_at:
        return jsonify({
            "success": False,
            "message": "OTP expired"
        }), 400

    return jsonify({
        "success": True,
        "message": "OTP verified successfully"
    }), 200


# =========================================================
# USER: COMPLETE REGISTRATION
# =========================================================

def complete_registration():

    data = request.get_json() or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    otp = data.get("otp")

    if not username or not email or not password or not otp:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    username = username.strip()
    email = email.strip().lower()
    otp = str(otp).strip()

    # Check admin authorization
    authorized_user = AuthorizedUser.query.filter_by(
        email=email,
        used=False
    ).first()

    if not authorized_user:
        return jsonify({
            "success": False,
            "message": "Email is not authorized by admin"
        }), 403

    # Check OTP
    record = RegistrationOTP.query.filter_by(
        email=email,
        otp=otp,
        used=False
    ).first()

    if not record:
        return jsonify({
            "success": False,
            "message": "Invalid OTP"
        }), 400

    # Check OTP expiry
    if datetime.utcnow() > record.expires_at:
        return jsonify({
            "success": False,
            "message": "OTP expired"
        }), 400

    # Check username
    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username:
        return jsonify({
            "success": False,
            "message": "Username already exists"
        }), 400

    # Check email
    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email:
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 400

    # Create user
    user = User(
        username=username,
        email=email,
        role="analyst"
    )

    # Hash password correctly
    user.set_password(password)

    db.session.add(user)

    # Mark OTP as used
    record.used = True

    # Mark authorization as used
    authorized_user.used = True

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Registration successful. You can now login."
    }), 201