import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key")
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:ZABRKNTxFDsMLAWgzQLubWgyzBlGXftl@crossover.proxy.rlwy.net:54959/railway"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
