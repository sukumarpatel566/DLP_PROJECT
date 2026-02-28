from datetime import datetime
from extensions import db, bcrypt


# ==========================
# USER MODEL
# ==========================
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_locked = db.Column(db.Boolean, default=False)
    profile_photo = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Set password
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Check password
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


# ==========================
# FILE MODEL
# ==========================
class File(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False
    )

    filename = db.Column(db.String(255), nullable=False)
    encrypted_path = db.Column(db.String(500), nullable=False)

    is_blocked = db.Column(db.Boolean, default=False)
    detected_types = db.Column(db.Text, nullable=True)
    filesize = db.Column(db.Integer, nullable=True)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='Low')

    upload_time = db.Column(db.DateTime, default=datetime.utcnow)


# ==========================
# ACTIVITY LOG MODEL
# ==========================
class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True
    )

    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ==========================
# ANOMALY LOG MODEL
# ==========================
class AnomalyLog(db.Model):
    __tablename__ = 'anomaly_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False
    )

    anomaly_type = db.Column(db.String(100), nullable=False)

    severity = db.Column(
        db.String(20),
        default='Medium'
    )

    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)