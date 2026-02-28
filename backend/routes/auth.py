from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import db, User, Log
from extensions import bcrypt
from datetime import timedelta
from sqlalchemy import or_
from werkzeug.utils import secure_filename
import datetime
import os

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Invalid input"}), 400

        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()
        role = data.get("role", "user").lower()

        if not username or not email or not password:
            return jsonify({"success": False, "message": "All fields are required"}), 400

        if len(password) < 6:
            return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400

        if role not in ["admin", "user"]:
            return jsonify({"success": False, "message": "Invalid role. Use 'admin' or 'user'"}), 400

        # Check if user already exists
        existing_user = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()

        if existing_user:
            return jsonify({"success": False, "message": "Username or Email already exists"}), 400

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "User registered successfully",
            "data": {"username": username, "role": role}
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": "Registration failed", "error": str(e)}), 500

@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Invalid input"}), 400

        identifier = data.get("email") or data.get("username")
        password = data.get("password")

        if not identifier or not password:
            return jsonify({"success": False, "message": "Missing identifier or password"}), 400

        identifier = identifier.strip()
        password = password.strip()

        # Find user by email OR username
        user = User.query.filter(
            or_(User.email == identifier, User.username == identifier)
        ).first()

        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            return jsonify({"success": False, "message": "Invalid email or password"}), 401

        # Check if user is locked
        if user.is_locked:
            return jsonify({
                "success": False,
                "message": "Account temporarily locked due to repeated high-risk uploads."
            }), 403

        # Identity MUST be a string for JWT
        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(days=1)
        )

        # Log login activity
        login_log = Log(
            user_id=user.id,
            action="Login",
            details="User logged in successfully",
            ip_address=request.remote_addr
        )

        db.session.add(login_log)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "Login successful",
            "data": {
                "access_token": access_token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "role": user.role
                }
            }
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": "Login failed", "error": str(e)}), 500

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        return jsonify({
            "success": True,
            "data": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "profile_photo": user.profile_photo,
                "created_at": user.created_at.isoformat()
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": "Failed to fetch user data", "error": str(e)}), 500

@auth_bp.route("/change-password", methods=["POST"])
@jwt_required()
def change_password():
    try:
        data = request.get_json()
        current_password = data.get("current_password")
        new_password = data.get("new_password")

        if not current_password or not new_password:
            return jsonify({"success": False, "message": "Missing passwords"}), 400

        if len(new_password) < 6:
            return jsonify({"success": False, "message": "New password must be at least 6 characters"}), 400

        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user or not bcrypt.check_password_hash(user.password_hash, current_password):
            return jsonify({"success": False, "message": "Invalid current password"}), 401

        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        return jsonify({"success": True, "message": "Password updated successfully"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": "Failed to change password", "error": str(e)}), 500

@auth_bp.route("/upload-profile-photo", methods=["POST"])
@jwt_required()
def upload_profile_photo():
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "message": "No file part"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "message": "No selected file"}), 400

        if file:
            filename = secure_filename(file.filename)
            user_id = get_jwt_identity()
            # unique filename per user
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'png'
            new_filename = f"user_{user_id}_{int(datetime.datetime.now().timestamp())}.{ext}"
            
            upload_folder = os.path.join('uploads', 'profile_photos')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            file_path = os.path.join(upload_folder, new_filename)
            file.save(file_path)

            user = User.query.get(user_id)
            # URL to access the photo (assuming /uploads/profile_photos/<filename>)
            user.profile_photo = f"/uploads/profile_photos/{new_filename}"
            db.session.commit()

            return jsonify({
                "success": True, 
                "message": "Profile photo uploaded",
                "data": {"profile_photo": user.profile_photo}
            }), 200
            
    except Exception as e:
        return jsonify({"success": False, "message": "Upload failed", "error": str(e)}), 500

@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    # Typically JWT logout is handled on the frontend by clearing the token
    # This endpoint is here for consistency and optional logging
    return jsonify({"success": True, "message": "Logged out successfully"}), 200
