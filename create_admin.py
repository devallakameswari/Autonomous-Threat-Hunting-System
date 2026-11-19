
from app import app
from Database.database import db
from Database.seed_data import create_admin

with app.app_context():
    db.create_all()
    create_admin()

