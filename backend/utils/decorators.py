from functools import wraps
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask import jsonify
from models import User

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            # JWT identity is stored as a string, convert to int for query
            user_id = int(get_jwt_identity())
            user = User.query.get(user_id)
            if not user or user.role.lower() != 'admin':
                return jsonify({"success": False, "message": "Admin access required"}), 403
            return fn(*args, **kwargs)
        except Exception as e:
            return jsonify({"success": False, "message": "Authentication failed", "error": str(e)}), 401
    return wrapper

def role_required(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = int(get_jwt_identity())
                user = User.query.get(user_id)
                if not user or user.role.lower() != role.lower():
                    return jsonify({"success": False, "message": f"{role} access required"}), 403
                return fn(*args, **kwargs)
            except Exception as e:
                return jsonify({"success": False, "message": "Authentication failed", "error": str(e)}), 401
        return wrapper
    return decorator
