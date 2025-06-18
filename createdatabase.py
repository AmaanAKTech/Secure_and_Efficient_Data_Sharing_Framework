import os
import sqlite3

SECURE_FOLDER = 'secure_folder'
os.makedirs(SECURE_FOLDER, exist_ok=True)

DATABASE = 'files.db'

def init_db():
    """Initialize the SQLite database with enhanced file tracking."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            original_filename TEXT,
            encrypted_filename TEXT,
            encryption_key TEXT,
            md5_hash TEXT,
            file_size INTEGER,
            file_type TEXT,
            upload_date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()