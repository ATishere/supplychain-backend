import mysql.connector
import os

def get_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "mysql-1dd7ba9f-at080-8109.g.aivencloud.com"),
        port=int(os.environ.get("DB_PORT", 24634)),
        user=os.environ.get("DB_USER", "avnadmin"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME", "defaultdb"),
        connection_timeout=30,
        ssl_disabled=False  # Bắt buộc False để dùng SSL của Aiven
    )