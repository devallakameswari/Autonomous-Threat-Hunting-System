from app import app
from Database.database import db
from Database.models import LoginActivity


with app.app_context():

    count = LoginActivity.query.count()

    LoginActivity.query.delete(
        synchronize_session=False
    )

    db.session.commit()

    print(f"Deleted {count} old login activity records.")
    print("Login activity has been reset to 0.")