import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database configuration with PyMySQL driver
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security keys
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    AES_KEY = os.getenv("AES_KEY")
    
    # App settings
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = FLASK_ENV == "development"
