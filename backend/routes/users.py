from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, File, AnomalyLog, User
from sqlalchemy import func

users_bp = Blueprint('users', __name__)

@users_bp.route('/risk-profile', methods=['GET'])
@jwt_required()
def get_risk_profile():
    try:
        user_id = int(get_jwt_identity())
        
        total_uploads = File.query.filter_by(user_id=user_id).count()
        
        if total_uploads == 0:
            return jsonify({
                "success": True,
                "data": {
                    "total_uploads": 0,
                    "average_risk": 0,
                    "high_risk_percentage": 0,
                    "recent_anomalies": 0,
                    "risk_status": "Normal"
                }
            }), 200

        avg_risk = db.session.query(func.avg(File.risk_score)).filter(File.user_id == user_id).scalar() or 0
        high_risk_count = File.query.filter(
            File.user_id == user_id, 
            File.risk_level.in_(['High', 'Critical'])
        ).count()
        
        recent_anomalies = AnomalyLog.query.filter_by(user_id=user_id).count()
        
        percentage = (high_risk_count / total_uploads) * 100
        
        risk_status = "Normal"
        if percentage > 30 or recent_anomalies > 5:
            risk_status = "High Risk User"
        elif percentage > 10 or recent_anomalies > 2:
            risk_status = "Suspicious"
            
        return jsonify({
            "success": True,
            "data": {
                "total_uploads": total_uploads,
                "average_risk": round(float(avg_risk), 2),
                "high_risk_percentage": round(percentage, 2),
                "recent_anomalies": recent_anomalies,
                "risk_status": risk_status
            }
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
