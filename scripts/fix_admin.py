from werkzeug.security import generate_password_hash
import sqlite3
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.security_utils import encrypt_data

def fix_admin():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # 1. Reset Admin Password
    new_password = "maggie"
    hashed = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE username = 'Dhruvi'", (hashed,))
    print(f"[Fix] Admin 'Dhruvi' password reset to: {new_password}")
    
    # 2. Encrypt SMTP Password in settings
    # Get plain text from .env (as it was in .env)
    plain_smtp = "ctlj dzex ycrb zfqk"
    encrypted_smtp = encrypt_data(plain_smtp)
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('MAIL_PASSWORD', ?)", (encrypted_smtp,))
    print("[Fix] SMTP password encrypted in database settings.")
    
    conn.commit()
    conn.close()
    print("[Fix] Admin account fixed successfully.")

if __name__ == "__main__":
    if not os.environ.get("ENCRYPTION_KEY"):
        # Set it for this process if missing (using the one from .env)
        os.environ["ENCRYPTION_KEY"] = "I-p9P6neihZaq-WGdguClMTtPCHV8GlUkq_wU5jamHQ="
    
    fix_admin()
