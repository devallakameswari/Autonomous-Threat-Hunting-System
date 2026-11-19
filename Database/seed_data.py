

from Database.database import db
from Database.models import User


def create_admin():
    admin = User.query.filter_by(username="admin").first()

    if admin:
        print("Admin user already exists.")

        # Make sure the account is actually an admin
        admin.role = "admin"
        admin.set_password("admin123")
        db.session.commit()

        print("Admin account password has been reset.")
        return admin

    admin = User(
        username="admin",
        email="admin@example.com",
        role="admin"
    )

    admin.set_password("admin123")

    db.session.add(admin)
    db.session.commit()

    print("=" * 50)
    print("ADMIN ACCOUNT CREATED")
    print("=" * 50)
    print("Username : admin")
    print("Password : admin123")
    print("Email    : admin@example.com")
    print("Role     : admin")
    print("=" * 50)

    return admin
