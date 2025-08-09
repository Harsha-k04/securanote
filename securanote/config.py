import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key")
    SQLALCHEMY_DATABASE_URI = "postgresql://securanote_user:OsKWfhyrOmeJueiEw3UmNVUVH9TrqDVG@dpg-d285r8m3jp1c7380kvn0-a.oregon-postgres.render.com/securanote_db?sslmode=require"
    SQLALCHEMY_TRACK_MODIFICATIONS = False