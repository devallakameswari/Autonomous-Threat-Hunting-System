"""
Database/init_db.py
Standalone initializer: creates all tables and seeds a default admin user.

Run directly:
    python -m Database.init_db
"""

import os
import sys

# Allow running this file directly from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask
from config import Config
from Database.database import db, init_app
from Database.models import User


def create_app_for_db():
    app = Flask(__name__)
    app.config.from_object(Config)
    init_app(app)
    return app


def seed_admin(app):
    with app.app_context():
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_email = os.getenv("ADMIN_EMAIL", "devallakameswari0@gmail.com")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin@123")

        existing = User.query.filter_by(username=admin_username).first()
        if existing:
            print(f"[init_db] Admin user '{admin_username}' already exists. Skipping seed.")
            return

        admin = User(username=admin_username, email=admin_email, role="admin")
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print(f"[init_db] Created admin user '{admin_username}' with the password from .env")


if __name__ == "__main__":
    flask_app = create_app_for_db()
    print("[init_db] Database tables created (if not already present).")
    seed_admin(flask_app)
    print("[init_db] Done.")
