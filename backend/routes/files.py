from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import User, File, Log, AnomalyLog
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
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        if user and user.is_locked:
            return jsonify({
                "success": False, 
                "message": "Account temporarily locked due to repeated high-risk uploads."
            }), 403

        if 'file' not in request.files:
            return jsonify({"success": False, "message": "No file part"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "message": "No selected file"}), 400

        filename = secure_filename(file.filename)
        file_content = file.read()
        file_size = len(file_content)

        if file_size == 0:
            return jsonify({"success": False, "message": "Empty file"}), 400

        # 1. DLP Scanning & Risk Scoring
        detected_counts = dlp_engine.scan_file(io.BytesIO(file_content), filename)
        detected_labels = list(detected_counts.keys())
        is_blocked = len(detected_labels) > 0

        risk_points_map = {
            "Credit Card": 50,
            "Aadhaar": 40,
            "PAN Card": 35,
            "Email Address": 10,
            "Phone Number": 10,
            "API Key": 30,
            "Password String": 40
        }
        
        total_risk_score = 0
        for label, count in detected_counts.items():
            points = risk_points_map.get(label, 10)
            total_risk_score += points * count
            
        risk_level = "Low"
        if total_risk_score > 100: risk_level = "Critical"
        elif total_risk_score > 60: risk_level = "High"
        elif total_risk_score > 20: risk_level = "Medium"

        # 2. Anomaly Detection & Locking Logic
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        if risk_level == "Critical":
            critical_uploads_count = File.query.filter(
                File.user_id == user_id,
                File.risk_level == "Critical",
                File.upload_time >= one_hour_ago
            ).count()
            
            if critical_uploads_count >= 2: # This is the 3rd one
                user.is_locked = True
                db.session.add(Log(
                    user_id=user_id,
                    action="Account Locked",
                    details=f"User locked due to 3+ Critical uploads in 1 hour.",
                    ip_address=request.remote_addr
                ))
                db.session.commit()
                return jsonify({
                    "success": False, 
                    "message": "Account temporarily locked due to repeated high-risk uploads."
                }), 403

        recent_uploads_count = File.query.filter(
            File.user_id == user_id,
            File.upload_time >= one_hour_ago
        ).count()
        
        anomalies = anomaly_service.check_upload_anomaly(user_id, file_size, recent_uploads_count)
        for anomaly in anomalies:
            db.session.add(AnomalyLog(
                user_id=user_id,
                anomaly_type=anomaly.get('type'),
                severity=anomaly.get('severity', 'Medium'),
                details=anomaly.get('details')
            ))

        # 3. Encryption and Storage
        upload_dir = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)

        temp_path = os.path.join(upload_dir, f"temp_{filename}")
        with open(temp_path, 'wb') as f:
            f.write(file_content)
        
        encrypted_filename = f"enc_{filename}"
        encrypted_path = os.path.join(upload_dir, encrypted_filename)
        encryption_service.encrypt_file(temp_path, encrypted_path)
        os.remove(temp_path)

        # 4. Save to DB
        new_file = File(
            user_id=user_id,
            filename=filename,
            encrypted_path=encrypted_path,
            is_blocked=is_blocked,
            detected_types=",".join(detected_labels) if detected_labels else None,
            filesize=file_size,
            risk_score=total_risk_score,
            risk_level=risk_level
        )
        
        db.session.add(new_file)
        db.session.add(Log(
            user_id=user_id, 
            action="File Upload", 
            details=f"File: {filename}, Risk: {risk_level} ({total_risk_score})",
            ip_address=request.remote_addr
        ))
        
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "File processed successfully.",
            "data": {
                "risk_score": total_risk_score,
                "risk_level": risk_level,
                "is_blocked": is_blocked
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Upload Error: {str(e)}")
        return jsonify({"success": False, "message": "Upload failed", "error": str(e)}), 500

@files_bp.route('/my-files', methods=['GET'])
@jwt_required()
def get_my_files():
    try:
        user_id = int(get_jwt_identity())
        
        # Filtering parameters
        risk = request.args.get('risk')
        blocked = request.args.get('blocked')
        search = request.args.get('search')
        date_from = request.args.get('date_from')

        query = File.query.filter_by(user_id=user_id)

        if risk:
            query = query.filter(File.risk_level == risk)
        if blocked:
            query = query.filter(File.is_blocked == (blocked.lower() == 'true'))
        if search:
            query = query.filter(File.filename.like(f"%{search}%"))
        if date_from:
            try:
                dt = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(File.upload_time >= dt)
            except ValueError:
                pass

        files = query.order_by(File.upload_time.desc()).all()

        return jsonify({
            "success": True,
            "message": "Files retrieved successfully",
            "data": [{
                "id": f.id,
                "filename": f.filename,
                "is_blocked": f.is_blocked,
                "detected_types": f.detected_types,
                "filesize": f.filesize,
                "risk_score": f.risk_score,
                "risk_level": f.risk_level,
                "upload_time": f.upload_time.isoformat()
            } for f in files]
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": "Failed to fetch files", "error": str(e)}), 500

    except Exception as e:
        current_app.logger.error(f"My Files Error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to fetch files",
            "error": str(e)
        }), 500