from app import app, db
from model.Profile import Profile

with app.app_context():
    db.create_all()
    print("Database tables created/verified.")
