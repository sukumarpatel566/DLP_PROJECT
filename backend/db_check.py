import os
from dotenv import load_dotenv
import pymysql

load_dotenv()
db_url = os.getenv('DATABASE_URL')
# mysql+pymysql://root:password@localhost/dlp_db
try:
    # Manual parse for simple connection
    creds = db_url.split('://')[1].split('@')[0].split(':')
    host_db = db_url.split('@')[1].split('/')
    
    user = creds[0]
    password = creds[1]
    host = host_db[0]
    db_name = host_db[1]

    connection = pymysql.connect(
        host=host,
        user=user,
        password=password,
        database=db_name
    )

    with connection.cursor() as cursor:
        print("Checking 'files' table columns:")
        cursor.execute("DESCRIBE files")
        for row in cursor.fetchall():
            print(row)
            
        print("\nChecking 'logs' table columns:")
        cursor.execute("DESCRIBE logs")
        for row in cursor.fetchall():
            print(row)

finally:
    if 'connection' in locals():
        connection.close()
