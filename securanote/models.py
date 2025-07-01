from datetime import datetime
from securanote import db
from flask_login import UserMixin
from sqlalchemy import LargeBinary
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import DateTime, Integer

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(256), nullable=False)
    notes = db.relationship('Note', backref='owner', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class Note(db.Model):
    __tablename__ = 'notes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    encryption_type = db.Column(db.String(20), nullable=False)  # AES or ChaCha
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    pin_hash = db.Column(db.String(255), nullable=False)  # Store hashed PIN securely
    file_path = db.Column(db.String(255))  # e.g., 'uploads/myphoto.jpg'
    file_data = db.Column(LargeBinary)
    share_token = db.Column(db.String(100), unique=True, nullable=True)
    share_expiry = db.Column(DateTime, nullable=True)
    views_left = db.Column(Integer, default=0)
    wrong_attempts = db.Column(db.Integer, default=0)
    otp_code = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)



    def __repr__(self):
        return f"<Note {self.title}>"
