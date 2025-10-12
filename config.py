import os
import mysql.connector
from urllib.parse import urlparse

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")

    if db_url:
        # Parse the Railway MySQL connection URL
        url = urlparse(db_url)
        return mysql.connector.connect(
            host=url.hostname,
            user=url.username,
            password=url.password,
            database=url.path[1:],  # remove leading '/'
            port=url.port
        )
    else:
        # Local fallback for development
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="incident_reporting"
        )
