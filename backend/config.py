import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ==========================
    # DATABASE
    # ==========================
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://root:password@localhost/dlp_system"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ==========================
    # SECURITY KEYS
    # ==========================
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-jwt-key")
    SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-flask-key")

    AES_KEY = os.getenv("AES_KEY", "default-aes-key")

    # ==========================
    # FILE UPLOAD SETTINGS
    # ==========================
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit

    # ==========================
    # ENV SETTINGS
    # ==========================
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = FLASK_ENV == "development"