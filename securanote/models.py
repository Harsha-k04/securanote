from datetime import datetime
from flask_login import UserMixin

# -------------------------------
# User model for Flask-Login (Supabase)
# -------------------------------
class User(UserMixin):
    def __init__(self, id, username, email, is_verified=False, last_ip=None, last_login_time=None, created_at=None):
        self.id = id
        self.username = username
        self.email = email
        self.is_verified = is_verified
        self.last_ip = last_ip
        self.last_login_time = last_login_time
        self.created_at = created_at or datetime.utcnow()

    @classmethod
    def from_dict(cls, data):
        return cls(
            id=data.get("id"),
            username=data.get("username"),
            email=data.get("email"),
            is_verified=data.get("is_verified", False),
            last_ip=data.get("last_ip"),
            last_login_time=data.get("last_login_time"),
            created_at=data.get("created_at")
        )

    def __repr__(self):
        return f"<User {self.username}>"


# -------------------------------
# Note model for Supabase
# -------------------------------
class Note:
    def __init__(self, id, user_id, title, encrypted_content, encryption_type, pin_hash,
                 file_path=None, file_data=None, share_token=None, share_expiry=None,
                 views_left=0, wrong_attempts=0, otp_code=None, otp_expiry=None,
                 timestamp=None):
        self.id = id
        self.user_id = user_id
        self.title = title
        self.encrypted_content = encrypted_content
        self.encryption_type = encryption_type
        self.pin_hash = pin_hash
        self.file_path = file_path
        self.file_data = file_data
        self.share_token = share_token
        self.share_expiry = share_expiry
        self.views_left = views_left
        self.wrong_attempts = wrong_attempts
        self.otp_code = otp_code
        self.otp_expiry = otp_expiry
        self.timestamp = timestamp or datetime.utcnow()

    @classmethod
    def from_dict(cls, data):
        return cls(
            id=data.get("id"),
            user_id=data.get("user_id"),
            title=data.get("title"),
            encrypted_content=data.get("encrypted_content"),
            encryption_type=data.get("encryption_type"),
            pin_hash=data.get("pin_hash"),
            file_path=data.get("file_path"),
            file_data=data.get("file_data"),
            share_token=data.get("share_token"),
            share_expiry=data.get("share_expiry"),
            views_left=data.get("views_left", 0),
            wrong_attempts=data.get("wrong_attempts", 0),
            otp_code=data.get("otp_code"),
            otp_expiry=data.get("otp_expiry"),
            timestamp=data.get("timestamp")
        )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "encrypted_content": self.encrypted_content,
            "encryption_type": self.encryption_type,
            "pin_hash": self.pin_hash,
            "file_path": self.file_path,
            "file_data": self.file_data,
            "share_token": self.share_token,
            "share_expiry": self.share_expiry,
            "views_left": self.views_left,
            "wrong_attempts": self.wrong_attempts,
            "otp_code": self.otp_code,
            "otp_expiry": self.otp_expiry,
            "timestamp": self.timestamp
        }

    def __repr__(self):
        return f"<Note {self.title}>"
