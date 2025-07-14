import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key")
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:teVVjuepQZrWQFlmjVngZJEcnHAVebmy@postgres.railway.internal:5432/railway"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
