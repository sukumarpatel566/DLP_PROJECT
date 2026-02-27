from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import File, Log, AnomalyLog
from services.dlp_engine import DLPEngine
from services.encryption_service import EncryptionService
from services.anomaly_service import AnomalyService
import os
from werkzeug.utils import secure_filename
import io
from datetime import datetime, timedelta

files_bp = Blueprint('files', __name__)
dlp_engine = DLPEngine()
encryption_service = EncryptionService()
anomaly_service = AnomalyService()


@files_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "message": "No file part"}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({"success": False, "message": "No selected file"}), 400

        user_id = int(get_jwt_identity())
        filename = secure_filename(file.filename)

        # Read file safely
        file_content = file.read()
        file_size = len(file_content)

        if file_size == 0:
            return jsonify({"success": False, "message": "Empty file"}), 400

        # =========================
        # 1️⃣ DLP SCANNING
        # =========================
        detected_types = dlp_engine.scan_file(io.BytesIO(file_content), filename)
        is_blocked = bool(detected_types)

        # =========================
        # 2️⃣ ANOMALY DETECTION
        # =========================
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)

        recent_uploads_count = File.query.filter(
            File.user_id == user_id,
            File.upload_time >= one_hour_ago
        ).count()

        anomalies = anomaly_service.check_upload_anomaly(
            user_id, file_size, recent_uploads_count
        )

        for anomaly in anomalies:
            db.session.add(AnomalyLog(
                user_id=user_id,
                anomaly_type=anomaly.get('type'),
                severity=anomaly.get('severity', 'Medium'),
                details=anomaly.get('details')
            ))

        # =========================
        # 3️⃣ SAVE + ENCRYPT
        # =========================
        upload_dir = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)

        temp_path = os.path.join(upload_dir, f"temp_{filename}")

        with open(temp_path, 'wb') as f:
            f.write(file_content)

        encrypted_filename = f"enc_{filename}"
        encrypted_path = os.path.join(upload_dir, encrypted_filename)

        encryption_service.encrypt_file(temp_path, encrypted_path)

        os.remove(temp_path)

        # =========================
        # 4️⃣ SAVE TO DATABASE
        # =========================
        new_file = File(
            user_id=user_id,
            filename=filename,
            encrypted_path=encrypted_path,
            is_blocked=is_blocked,
            detected_types=",".join(detected_types) if detected_types else None,
            filesize=file_size
        )

        db.session.add(new_file)

        db.session.add(Log(
            user_id=user_id,
            action="File Upload",
            details=f"File: {filename}, Blocked: {is_blocked}",
            ip_address=request.remote_addr
        ))

        db.session.commit()

        if is_blocked:
            return jsonify({
                "success": False,
                "status": "blocked",
                "message": "Sensitive data detected. File blocked.",
                "detected": detected_types
            }), 403

        return jsonify({
            "success": True,
            "status": "success",
            "message": "File uploaded and encrypted successfully."
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Upload Error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Upload failed",
            "error": str(e)
        }), 500


@files_bp.route('/my-files', methods=['GET'])
@jwt_required()
def get_my_files():
    try:
        user_id = int(get_jwt_identity())

        files = File.query.filter_by(user_id=user_id).all()

        return jsonify({
            "success": True,
            "message": "Files retrieved successfully",
            "data": [{
                "id": f.id,
                "filename": f.filename,
                "is_blocked": f.is_blocked,
                "detected_types": f.detected_types,
                "filesize": f.filesize,
                "upload_time": f.upload_time.isoformat()
            } for f in files]
        }), 200

    except Exception as e:
        current_app.logger.error(f"My Files Error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to fetch files",
            "error": str(e)
        }), 500