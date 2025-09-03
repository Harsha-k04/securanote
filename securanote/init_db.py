from securanote import app, db
from securanote.models import User, Note

with app.app_context():
    db.create_all()
    print("Tables created successfully!")
