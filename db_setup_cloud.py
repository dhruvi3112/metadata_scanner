"""
Cloud Database Setup Script for PostgreSQL (Neon.tech)
Run this ONCE to create the tables and default admin user in your cloud database.

Usage:
    DATABASE_URL="postgresql://user:pass@host/db?sslmode=require" python db_setup_cloud.py
"""
import os
import sys
from werkzeug.security import generate_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable is not set.")
    print('Usage: DATABASE_URL="postgresql://..." python db_setup_cloud.py')
    sys.exit(1)

try:
    import psycopg2
except ImportError:
    print("ERROR: psycopg2 is not installed. Run: pip install psycopg2-binary")
    sys.exit(1)

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

print("Connected to cloud database!")

# ── USERS TABLE ──
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    email_verified INTEGER DEFAULT 0,
    phone_number TEXT,
    two_fa_enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# ── SCAN HISTORY TABLE ──
cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    report_file TEXT NOT NULL,
    risk_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

# ── OTP CODES TABLE ──
cursor.execute("""
CREATE TABLE IF NOT EXISTS otp_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

# ── SETTINGS TABLE ──
cursor.execute("""
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
""")

# ── INSERT DEFAULT ADMIN ──
hashed = generate_password_hash("Password@123")
cursor.execute("""
INSERT INTO users (username, email, password, role, email_verified)
VALUES (%s, %s, %s, %s, 1)
ON CONFLICT (username) DO NOTHING
""", ("Dhruvi", "dhruvipanchal847@gmail.com", hashed, "admin"))

# ── INSERT DEFAULT SMTP SETTINGS ──
default_settings = {
    "MAIL_SERVER": "smtp.gmail.com",
    "MAIL_PORT": "465",
    "MAIL_USERNAME": "",
    "MAIL_PASSWORD": ""
}
for key, value in default_settings.items():
    cursor.execute("""
    INSERT INTO settings (key, value) VALUES (%s, %s)
    ON CONFLICT (key) DO NOTHING
    """, (key, value))

conn.commit()
conn.close()

print("\n" + "="*50)
print(" Cloud Database Setup Complete! ".center(50, "="))
print("="*50)
print("Tables created: users, scan_history, otp_codes, settings")
print("Admin user: Dhruvi (Password@123)")
print("You can now deploy to Koyeb or Render!")
