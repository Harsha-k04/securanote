import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key")
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:Harshithachu@db.vebmigukwzzptqdgdqtf.supabase.co:5432/postgres"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
