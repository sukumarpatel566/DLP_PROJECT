import pymysql
import os
from dotenv import load_dotenv

load_dotenv()

db_url = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@localhost/dlp_system")
# Extract connection details
# Format: mysql+pymysql://user:password@host/dbname
try:
    auth_part = db_url.split("//")[1].split("@")[0]
    user = auth_part.split(":")[0]
    password = auth_part.split(":")[1] if ":" in auth_part else ""
    
    host_part = db_url.split("@")[1].split("/")[0]
    host = host_part.split(":")[0]
    port = int(host_part.split(":")[1]) if ":" in host_part else 3306
    
    dbname = db_url.split("/")[-1]

    connection = pymysql.connect(
        host=host,
        user=user,
        password=password,
        database=dbname,
        port=port
    )

    with connection.cursor() as cursor:
        print(f"Checking columns in 'users' table...")
        cursor.execute("DESCRIBE users")
        columns = [row[0] for row in cursor.fetchall()]
        if 'is_locked' not in columns:
            print("Adding 'is_locked' to 'users' table...")
            cursor.execute("ALTER TABLE users ADD COLUMN is_locked BOOLEAN DEFAULT FALSE")
        else:
            print("'is_locked' column exists.")

        print(f"Checking columns in 'files' table...")
        cursor.execute("DESCRIBE files")
        columns = [row[0] for row in cursor.fetchall()]
        if 'risk_score' not in columns:
            print("Adding 'risk_score' to 'files' table...")
            cursor.execute("ALTER TABLE files ADD COLUMN risk_score INT DEFAULT 0")
        if 'risk_level' not in columns:
            print("Adding 'risk_level' to 'files' table...")
            cursor.execute("ALTER TABLE files ADD COLUMN risk_level VARCHAR(20) DEFAULT 'Low'")
        
        print("Schema update complete.")
    
    connection.commit()
    connection.close()
except Exception as e:
    print(f"Error: {e}")
