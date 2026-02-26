from flask import Blueprint, jsonify
from models import db, User, File, Log, AnomalyLog
from utils.decorators import admin_required
from sqlalchemy import func

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_stats():
    total_users = User.query.count()
    total_files = File.query.count()
    blocked_files = File.query.filter_by(is_blocked=True).count()
    
    # Uploads per day
    daily_uploads = db.session.query(
        func.date(File.upload_time).label('date'),
        func.count(File.id).label('count')
    ).group_by('date').all()
    
    # Sensitive types distribution
    all_files = File.query.filter(File.detected_types != None).all()
    type_counts = {}
    for f in all_files:
        for t in f.detected_types.split(','):
            type_counts[t] = type_counts.get(t, 0) + 1

    return jsonify({
        "success": True,
        "data": {
            "total_users": total_users,
            "total_files": total_files,
            "blocked_files": blocked_files,
            "daily_uploads": [{"date": str(d.date), "count": d.count} for d in daily_uploads],
            "type_distribution": [{"type": k, "value": v} for k, v in type_counts.items()]
        }
    }), 200

@admin_bp.route('/logs', methods=['GET'])
@admin_required
def get_all_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).limit(100).all()
    return jsonify({
        "success": True,
        "data": [{
            "id": l.id,
            "user_id": l.user_id,
            "action": l.action,
            "details": l.details,
            "ip": l.ip_address,
            "timestamp": l.timestamp.isoformat()
        } for l in logs]
    }), 200

@admin_bp.route('/anomalies', methods=['GET'])
@admin_required
def get_anomalies():
    anomalies = AnomalyLog.query.order_by(AnomalyLog.timestamp.desc()).all()
    return jsonify({
        "success": True,
        "data": [{
            "id": a.id,
            "user_id": a.user_id,
            "type": a.anomaly_type,
            "severity": a.severity,
            "details": a.details,
            "timestamp": a.timestamp.isoformat()
        } for a in anomalies]
    }), 200
