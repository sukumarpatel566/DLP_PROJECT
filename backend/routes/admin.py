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
        # Filter parameters
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        risk = request.args.get('risk')
        blocked = request.args.get('blocked')

        # Base query for stats calculation
        file_query = File.query
        anomaly_query = AnomalyLog.query
        
        if date_from:
            from_dt = datetime.strptime(date_from, '%Y-%m-%d')
            file_query = file_query.filter(File.upload_time >= from_dt)
            anomaly_query = anomaly_query.filter(AnomalyLog.timestamp >= from_dt)
        if date_to:
            to_dt = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            file_query = file_query.filter(File.upload_time < to_dt)
            anomaly_query = anomaly_query.filter(AnomalyLog.timestamp < to_dt)
        if risk:
            file_query = file_query.filter(File.risk_level == risk)
        if blocked:
            file_query = file_query.filter(File.is_blocked == (blocked.lower() == 'true'))

        total_users = User.query.count()
        total_files = file_query.count()
        blocked_files = file_query.filter_by(is_blocked=True).count()
        safe_files = total_files - blocked_files
        
        high_risk_files = file_query.filter(File.risk_level.in_(['High', 'Critical'])).count()
        
        # Trends (Last 7 Days - always dynamic or fixed?)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        daily_uploads = db.session.query(
            func.date(File.upload_time).label('date'),
            func.count(File.id).label('count')
        ).filter(File.upload_time >= seven_days_ago).group_by('date').all()
        
        # Anomalies
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        active_anomalies = AnomalyLog.query.filter(AnomalyLog.timestamp >= one_hour_ago).count()
        anomalies_24h = AnomalyLog.query.filter(AnomalyLog.timestamp >= (datetime.utcnow() - timedelta(days=1))).count()
        
        # Risk distribution
        risk_dist = db.session.query(
            File.risk_level, 
            func.count(File.id)
        ).filter(File.user_id.in_(db.session.query(User.id))).group_by(File.risk_level).all()
        # Note: filtered risk_dist doesn't make sense if we filter global stats, 
        # but let's keep it consistent with the overall query if parameters provided
        if risk or blocked or date_from or date_to:
             risk_dist = db.session.query(
                File.risk_level, 
                func.count(File.id)
            ).filter(File.id.in_(db.session.query(file_query.with_entities(File.id)))).group_by(File.risk_level).all()

        # Top 5 Risky Users
        top_risky_users = db.session.query(
            User.username,
            func.count(File.id).label('total_uploads'),
            func.avg(File.risk_score).label('avg_risk'),
            User.role
        ).join(File).group_by(User.id).order_by(func.avg(File.risk_score).desc()).limit(5).all()

        # Recent Security Activity (Last 10 Uploads)
        recent_uploads = file_query.order_by(File.upload_time.desc()).limit(10).all()

        return jsonify({
            "success": True,
            "data": {
                "total_users": total_users,
                "total_files": total_files,
                "blocked_files": blocked_files,
                "safe_files": safe_files,
                "high_risk_files_count": high_risk_files,
                "active_anomalies": active_anomalies,
                "anomalies_last_24h": anomalies_24h,
                "uploads_last_7_days": [{"date": str(d.date), "count": d.count} for d in daily_uploads],
                "risk_distribution": [{"level": r[0], "count": r[1]} for r in risk_dist],
                "top_risky_users": [{
                    "username": u[0],
                    "total_uploads": u[1],
                    "avg_risk": round(float(u[2]), 1),
                    "role": u[3]
                } for u in top_risky_users],
                "recent_activity": [{
                    "filename": f.filename,
                    "risk_level": f.risk_level,
                    "is_blocked": f.is_blocked,
                    "timestamp": f.upload_time.isoformat()
                } for f in recent_uploads]
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
