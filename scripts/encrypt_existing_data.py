import sys
import os

# Add the project root to sys.path so we can import app and database
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import get_db
from app.security_utils import encrypt_data, decrypt_data
from flask import Flask

# Create a minimal Flask app context to use get_db
app = Flask(__name__)

def migrate_smtp_passwords():
    with app.app_context():
        db = get_db()
        cursor = db.execute("SELECT key, value FROM settings WHERE key = 'MAIL_PASSWORD'")
        row = cursor.fetchone()
        
        if row:
            password = row["value"]
            # Check if it's already encrypted (Fernet tokens usually start with gAAAA)
            if password.startswith("gAAAA"):
                print("[Security] SMTP password already appears to be encrypted.")
            else:
                print(f"[Security] Encrypting plain-text SMTP password...")
                encrypted = encrypt_data(password)
                db.execute("UPDATE settings SET value = ? WHERE key = 'MAIL_PASSWORD'", (encrypted,))
                db.commit()
                print("[Security] Encryption successful.")
        else:
            print("[Security] No SMTP password found in database to encrypt.")

if __name__ == "__main__":
    if not os.environ.get("ENCRYPTION_KEY"):
        print("[Error] ENCRYPTION_KEY not found in environment!")
    else:
        migrate_smtp_passwords()
