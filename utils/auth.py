import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

def init_db(db_path):
    """Initialize the database and create necessary tables."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT,
            last_login TEXT
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_key TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vpn_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            config_name TEXT NOT NULL,
            server_country TEXT NOT NULL,
            encryption_key TEXT,
            created_at TEXT,
            last_used TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS intrusion_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            attempt_type TEXT,
            details TEXT,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        conn.commit()

def hash_password(password, salt=None):
    """Hash a password using SHA-256 and a salt."""
    if salt is None:
        salt = os.urandom(32)
    else:
        salt = bytes.fromhex(salt)

    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hashed.hex(), salt.hex()

def verify_password(password, stored_hash, salt):
    """Verify a password against the stored hash and salt."""
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == stored_hash

def register_user(db_path, username, password, email):
    """Register a new user if the username and email are unique."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False, "Username already exists"

            cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                return False, "Email already exists"

            password_hash, salt = hash_password(password)
            now = datetime.utcnow().isoformat()

            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, email, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt, email, now))

            conn.commit()
            return True, "User registered successfully"

    except sqlite3.Error as e:
        return False, f"Database error: {e}"

def login_user(db_path, username, password, ip_address):
    """Attempt to log in a user and create a session if successful."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user:
                log_intrusion(db_path, None, ip_address, "failed_login", f"Invalid username: {username}")
                return False, "Invalid username or password"

            user_id, stored_hash, salt = user

            if not verify_password(password, stored_hash, salt):
                log_intrusion(db_path, user_id, ip_address, "failed_login", f"Wrong password for {username}")
                return False, "Invalid username or password"

            # Update last login time
            cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow().isoformat(), user_id))

            # Create session
            session_key = os.urandom(32).hex()
            now = datetime.utcnow()
            expires_at = (now + timedelta(days=1)).isoformat()

            cursor.execute('''
                INSERT INTO sessions (user_id, session_key, ip_address, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, session_key, ip_address, now.isoformat(), expires_at))

            conn.commit()
            return True, {"user_id": user_id, "session_key": session_key}

    except sqlite3.Error as e:
        return False, f"Database error: {e}"

def verify_session(db_path, session_key, ip_address):
    """Verify a session's validity and check expiration and IP consistency."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT user_id, expires_at, ip_address FROM sessions WHERE session_key = ?", (session_key,))
            result = cursor.fetchone()

            if not result:
                return False, "Invalid session"

            user_id, expires_at_str, stored_ip = result
            expires_at = datetime.fromisoformat(expires_at_str)

            if datetime.utcnow() > expires_at:
                return False, "Session expired"

            if stored_ip != ip_address:
                log_intrusion(db_path, user_id, ip_address, "ip_change", f"IP changed from {stored_ip} to {ip_address}")
                return False, "Session invalid due to IP change"

            return True, {"user_id": user_id}

    except sqlite3.Error as e:
        return False, f"Database error: {e}"

def log_intrusion(db_path, user_id, ip_address, attempt_type, details):
    """Log intrusion attempts into the database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO intrusion_logs (user_id, ip_address, attempt_type, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, ip_address, attempt_type, details, datetime.utcnow().isoformat()))
            conn.commit()
    except sqlite3.Error as e:
        # Optional: print to console or log to file
        print(f"[WARN] Failed to log intrusion: {e}")
