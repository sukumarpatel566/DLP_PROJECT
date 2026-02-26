import os
from dotenv import load_dotenv
import pymysql

load_dotenv()
db_url = os.getenv('DATABASE_URL')
try:
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
        print("Detailed Column Check for 'files' table:")
        cursor.execute("SHOW COLUMNS FROM files")
        columns = cursor.fetchall()
        for col in columns:
            print(f"Col: '{col[0]}', Type: {col[1]}, Null: {col[2]}, Key: {col[3]}, Extra: {col[5]}")

        # Check if the column name has hidden characters
        for col in columns:
            if 'filesize' in col[0].lower():
                print(f"\nFOUND FILESIZE: '{col[0]}' (len: {len(col[0])})")
            if 'detected_types' in col[0].lower():
                print(f"FOUND DETECTED_TYPES: '{col[0]}' (len: {len(col[0])})")

finally:
    if 'connection' in locals():
        connection.close()
