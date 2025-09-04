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

    def __repr__(self):
        return f"<Note {self.title}>"
