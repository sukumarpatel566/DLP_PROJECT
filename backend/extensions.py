from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt

# Database instance
db = SQLAlchemy()

# JWT Manager
jwt = JWTManager()

# Password hashing
bcrypt = Bcrypt()