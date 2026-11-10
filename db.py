import mysql.connector
import os

def get_connection():
    # VULN-09 fix: no hardcoded fallbacks — all credentials must come from env vars
    host = os.environ.get("DB_HOST")
    if not host:
        raise EnvironmentError("DB_HOST is not set in environment variables")
    port_str = os.environ.get("DB_PORT")
    if not port_str:
        raise EnvironmentError("DB_PORT is not set in environment variables")
    user = os.environ.get("DB_USER")
    if not user:
        raise EnvironmentError("DB_USER is not set in environment variables")
    password = os.environ.get("DB_PASSWORD")
    if password is None:
        raise EnvironmentError("DB_PASSWORD is not set in environment variables")
    database = os.environ.get("DB_NAME")
    if not database:
        raise EnvironmentError("DB_NAME is not set in environment variables")
    return mysql.connector.connect(
        host=host,
        port=int(port_str),
        user=user,
        password=password,
        database=database,
        connection_timeout=30,
        ssl_disabled=False  # Bắt buộc False để dùng SSL của Aiven
    )