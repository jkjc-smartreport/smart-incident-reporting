import os
import mysql.connector
from urllib.parse import urlparse

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")

    if db_url and db_url.startswith("mysql://"):
        parsed = urlparse(db_url)
        return mysql.connector.connect(
            host=parsed.hostname,
            port=parsed.port,
            user=parsed.username,
            password=parsed.password,
            database=parsed.path.lstrip('/')
        )
    else:
        # fallback for local development
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="incident_reporting"
        )
