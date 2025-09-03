import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key")
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:hk04@localhost:5432/securanote_db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
