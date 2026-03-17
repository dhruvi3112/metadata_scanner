import sys
import os

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import get_db
from app.security_utils import encrypt_data, decrypt_data
from flask import Flask

app = Flask(__name__)

def migrate_data():
    with app.app_context():
        db = get_db()
        
        # 1. Migrate SMTP password
        cursor = db.execute("SELECT key, value FROM settings WHERE key = 'MAIL_PASSWORD'")
        row = cursor.fetchone()
        if row and not row["value"].startswith("gAAAA"):
            print("[Security] Encrypting plain-text SMTP password...")
            encrypted = encrypt_data(row["value"])
            db.execute("UPDATE settings SET value = ? WHERE key = 'MAIL_PASSWORD'", (encrypted,))
            print("[Security] SMTP password encrypted.")
        
        # 2. Migrate Scan History
        cursor = db.execute("SELECT id, filename, report_file FROM scan_history")
        rows = cursor.fetchall()
        count = 0
        for row in rows:
            if not row["filename"].startswith("gAAAA") or not row["report_file"].startswith("gAAAA"):
                enc_name = encrypt_data(row["filename"])
                enc_rep = encrypt_data(row["report_file"])
                db.execute(
                    "UPDATE scan_history SET filename = ?, report_file = ? WHERE id = ?",
                    (enc_name, enc_rep, row["id"])
                )
                count += 1
        
        db.commit()
        print(f"[Security] Migration complete. {count} scan records encrypted.")

if __name__ == "__main__":
    if not os.environ.get("ENCRYPTION_KEY"):
        print("[Error] ENCRYPTION_KEY required to run migration.")
    else:
        migrate_data()
