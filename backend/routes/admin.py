from flask import Blueprint, jsonify, send_file
from models import db, User, File, Log, AnomalyLog
from utils.decorators import admin_required
from sqlalchemy import func
from datetime import datetime, timedelta
from io import BytesIO

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_stats():
    try:
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
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route('/dashboard-stats', methods=['GET'])
@admin_required
def get_dashboard_stats():
    try:
        total_users = User.query.count()
        total_files = File.query.count()
        blocked_files = File.query.filter_by(is_blocked=True).count()
        safe_files = total_files - blocked_files
        
        high_risk_files = File.query.filter(File.risk_level.in_(['High', 'Critical'])).count()
        
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        daily_uploads = db.session.query(
            func.date(File.upload_time).label('date'),
            func.count(File.id).label('count')
        ).filter(File.upload_time >= seven_days_ago).group_by('date').all()
        
        anomalies_count = AnomalyLog.query.filter(AnomalyLog.timestamp >= seven_days_ago).count()
        
        risk_dist = db.session.query(
            File.risk_level, 
            func.count(File.id)
        ).group_by(File.risk_level).all()

        return jsonify({
            "success": True,
            "data": {
                "total_users": total_users,
                "total_files": total_files,
                "blocked_files": blocked_files,
                "safe_files": safe_files,
                "high_risk_files_count": high_risk_files,
                "uploads_last_7_days": [{"date": str(d.date), "count": d.count} for d in daily_uploads],
                "anomalies_last_7_days": anomalies_count,
                "risk_distribution": [{"level": r[0], "count": r[1]} for r in risk_dist]
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route('/logs', methods=['GET'])
@admin_required
def get_all_logs():
    try:
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
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route('/anomalies', methods=['GET'])
@admin_required
def get_anomalies():
    try:
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
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route('/export-report', methods=['GET'])
@admin_required
def export_report():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        total_files = File.query.count()
        blocked_files = File.query.filter_by(is_blocked=True).count()
        high_risk_files = File.query.filter(File.risk_level.in_(['High', 'Critical'])).count()
        
        top_risky_users = db.session.query(
            User.username, 
            func.count(File.id)
        ).join(File).filter(File.risk_level.in_(['High', 'Critical'])).group_by(User.username).order_by(func.count(File.id).desc()).limit(5).all()

        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        p.setFont("Helvetica-Bold", 20)
        p.drawCentredString(width/2, height - 50, "DLP Security Compliance Report")
        p.setFont("Helvetica", 12)
        p.drawCentredString(width/2, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, height - 120, "1. Executive Summary")
        p.setFont("Helvetica", 12)
        p.drawString(70, height - 140, f"- Total Files Scanned: {total_files}")
        p.drawString(70, height - 160, f"- Blocked Sensitive Files: {blocked_files}")
        p.drawString(70, height - 180, f"- High/Critical Risk Violations: {high_risk_files}")

        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, height - 220, "2. Top Risky Users")
        y = height - 240
        for user, count in top_risky_users:
            p.setFont("Helvetica", 12)
            p.drawString(70, y, f"- {user}: {count} severe violations")
            y -= 20

        p.setFont("Helvetica-Oblique", 10)
        p.drawString(50, 50, "Confidential - Intelligent DLP System Security Report")

        p.showPage()
        p.save()
        
        buffer.seek(0)
        return send_file(
            buffer, 
            as_attachment=True, 
            download_name='dlp_security_report.pdf', 
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({"success": False, "message": f"PDF Generation Error: {str(e)}"}), 500
