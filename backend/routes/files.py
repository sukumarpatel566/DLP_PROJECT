from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, File, Log, AnomalyLog
from services.dlp_engine import DLPEngine
from services.encryption_service import EncryptionService
from services.anomaly_service import AnomalyService
import os
from werkzeug.utils import secure_filename
import io

files_bp = Blueprint('files', __name__)
dlp_engine = DLPEngine()
encryption_service = EncryptionService()
anomaly_service = AnomalyService()

UPLOAD_FOLDER = 'backend/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@files_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({"msg": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400

    user_id = get_jwt_identity()
    filename = secure_filename(file.filename)
    file_content = file.read()
    file_size = len(file_content)

    # 1. DLP Scanning
    detected_types = dlp_engine.scan_file(io.BytesIO(file_content), filename)
    is_blocked = len(detected_types) > 0

    # 2. Anomaly Detection
    recent_uploads_count = File.query.filter(
        File.user_id == user_id,
        File.upload_time >= db.func.now() - db.text("interval 1 hour")
    ).count()
    
    anomalies = anomaly_service.check_upload_anomaly(user_id, file_size, recent_uploads_count)
    for anomaly in anomalies:
        new_anomaly = AnomalyLog(
            user_id=user_id,
            anomaly_type=anomaly['type'],
            severity=anomaly['severity'],
            details=anomaly['details']
        )
        db.session.add(new_anomaly)

    # 3. Encryption and Storage
    temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{filename}")
    with open(temp_path, 'wb') as f:
        f.write(file_content)
    
    encrypted_filename = f"enc_{filename}"
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
    encryption_service.encrypt_file(temp_path, encrypted_path)
    os.remove(temp_path)

    # 4. Save to DB
    new_file = File(
        user_id=user_id,
        filename=filename,
        encrypted_path=encrypted_path,
        is_blocked=is_blocked,
        detected_types=",".join(detected_types) if detected_types else None,
        filesize=file_size
    )
    
    db.session.add(new_file)
    
    log = Log(
        user_id=user_id, 
        action="File Upload", 
        details=f"File: {filename}, Blocked: {is_blocked}",
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.commit()

    if is_blocked:
        return jsonify({
            "success": False,
            "status": "blocked",
            "detected": detected_types,
            "message": "File contains sensitive data and has been blocked."
        }), 403

    return jsonify({
        "success": True,
        "status": "success",
        "message": "File uploaded and encrypted successfully."
    }), 201

@files_bp.route('/my-files', methods=['GET'])
@jwt_required()
def get_my_files():
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
            "upload_time": f.upload_time.isoformat()
        } for f in files]
    }), 200
