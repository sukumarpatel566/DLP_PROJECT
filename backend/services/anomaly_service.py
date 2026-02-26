from datetime import datetime, timedelta

class AnomalyService:
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.THRESHOLDS = {
            'uploads_per_hour': 10,
            'max_file_size_mb': 50,
            'failed_logins': 5
        }

    def check_upload_anomaly(self, user_id, file_size_bytes, recent_uploads_count):
        anomalies = []
        
        # 1. Frequency check
        if recent_uploads_count > self.THRESHOLDS['uploads_per_hour']:
            anomalies.append({
                'type': 'High Upload Frequency',
                'severity': 'Medium',
                'details': f'User uploaded {recent_uploads_count} files in the last hour.'
            })
            
        # 2. Large file check
        file_size_mb = file_size_bytes / (1024 * 1024)
        if file_size_mb > self.THRESHOLDS['max_file_size_mb']:
            anomalies.append({
                'type': 'Large File Upload',
                'severity': 'Low',
                'details': f'User uploaded a file of size {file_size_mb:.2f} MB.'
            })
            
        return anomalies

    def check_login_anomaly(self, user_id, failed_attempts):
        if failed_attempts >= self.THRESHOLDS['failed_logins']:
            return {
                'type': 'Brute Force Attempt',
                'severity': 'High',
                'details': f'User had {failed_attempts} failed login attempts.'
            }
        return None
