import random
import string
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from database import get_db


def generate_otp(length=6):
    """Generate a random numeric OTP code."""
    return ''.join(random.choices(string.digits, k=length))


def store_otp(user_id, code, purpose):
    """
    Store an OTP in the database with a 10-minute expiry.
    Invalidates any previous unused OTPs for the same user+purpose.
    purpose: 'email_verify' or 'login_2fa'
    """
    db = get_db()

    # Invalidate old unused OTPs for this user+purpose
    db.execute(
        "UPDATE otp_codes SET used = 1 WHERE user_id = ? AND purpose = ? AND used = 0",
        (user_id, purpose)
    )

    expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.execute(
        """INSERT INTO otp_codes (user_id, code, purpose, created_at, expires_at, used)
           VALUES (?, ?, ?, ?, ?, 0)""",
        (user_id, code, purpose, datetime.utcnow(), expires_at)
    )
    db.commit()


def verify_otp(user_id, code, purpose):
    """
    Verify an OTP. Returns (True, None) on success or (False, error_message) on failure.
    Marks the OTP as used if valid.
    """
    db = get_db()
    otp_row = db.execute(
        """SELECT * FROM otp_codes
           WHERE user_id = ? AND code = ? AND purpose = ? AND used = 0
           ORDER BY created_at DESC LIMIT 1""",
        (user_id, code, purpose)
    ).fetchone()

    if not otp_row:
        return False, "Invalid OTP code. Please try again."

    raw_expires = otp_row["expires_at"]
    if isinstance(raw_expires, str):
        try:
            expires_at = datetime.strptime(raw_expires, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            expires_at = datetime.strptime(raw_expires, "%Y-%m-%d %H:%M:%S")
    else:
        expires_at = raw_expires  # PostgreSQL returns a datetime object directly

    if datetime.utcnow() > expires_at:
        return False, "OTP has expired. Please request a new one."

    # Mark as used
    db.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_row["id"],))
    db.commit()

    return True, None


def send_otp_email(to_email, code, purpose):
    """
    Send an OTP code via email using SMTP.
    Prioritizes DB settings, falls back to environment variables.
    Returns True on success, False on failure.
    """
    db = get_db()
    db_settings = db.execute("SELECT key, value FROM settings").fetchall()
    settings_dict = {row["key"]: row["value"] for row in db_settings}

    mail_username = (settings_dict.get("MAIL_USERNAME") or os.environ.get("MAIL_USERNAME", "")).strip()
    mail_password = (settings_dict.get("MAIL_PASSWORD") or os.environ.get("MAIL_PASSWORD", "")).strip().replace(" ", "")
    mail_server = (settings_dict.get("MAIL_SERVER") or os.environ.get("MAIL_SERVER", "smtp.gmail.com")).strip()
    mail_port_str = (settings_dict.get("MAIL_PORT") or os.environ.get("MAIL_PORT", "587")).strip()
    try:
        mail_port = int(mail_port_str)
    except:
        mail_port = 587

    if not mail_username or not mail_password:
        print("\n" + "!"*60)
        print(" [OTP] WARNING: SMTP CONFIGURATION MISSING ".center(60, "!"))
        print(f" [OTP] Please configure SMTP settings in the Admin Dashboard.")
        print(f" [OTP] Destination: {to_email}")
        print(f" [OTP] Code:        {code}")
        print(f" [OTP] Purpose:     {purpose}")
        print("!"*60 + "\n")
        return True, None  # Return True to allow login with the code from the console

    subject_map = {
        "email_verify": "Verify Your Email — Metadata Scanner",
        "login_2fa": "Your Login Verification Code — Metadata Scanner"
    }
    body_map = {
        "email_verify": f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 30px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-radius: 16px; color: #e2e8f0;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="display: inline-block; width: 56px; height: 56px; background: rgba(16, 185, 129, 0.15); border-radius: 50%; line-height: 56px; font-size: 24px;">🛡️</div>
                <h2 style="color: #10b981; margin: 12px 0 4px;">Verify Your Email</h2>
                <p style="color: #94a3b8; font-size: 14px;">Complete your registration with the code below</p>
            </div>
            <div style="background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 12px; padding: 20px; text-align: center; margin: 20px 0;">
                <p style="color: #94a3b8; font-size: 13px; margin: 0 0 8px;">Your verification code</p>
                <div style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #6366f1;">{code}</div>
            </div>
            <p style="color: #94a3b8; font-size: 13px; text-align: center;">This code expires in <strong style="color: #e2e8f0;">10 minutes</strong>.</p>
            <hr style="border: none; border-top: 1px solid rgba(148, 163, 184, 0.1); margin: 24px 0;">
            <p style="color: #64748b; font-size: 12px; text-align: center;">If you didn't create an account, ignore this email.</p>
        </div>
        """,
        "login_2fa": f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 30px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-radius: 16px; color: #e2e8f0;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="display: inline-block; width: 56px; height: 56px; background: rgba(99, 102, 241, 0.15); border-radius: 50%; line-height: 56px; font-size: 24px;">🔐</div>
                <h2 style="color: #6366f1; margin: 12px 0 4px;">Two-Factor Authentication</h2>
                <p style="color: #94a3b8; font-size: 14px;">Enter this code to complete your login</p>
            </div>
            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px; padding: 20px; text-align: center; margin: 20px 0;">
                <p style="color: #94a3b8; font-size: 13px; margin: 0 0 8px;">Your login code</p>
                <div style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #10b981;">{code}</div>
            </div>
            <p style="color: #94a3b8; font-size: 13px; text-align: center;">This code expires in <strong style="color: #e2e8f0;">10 minutes</strong>.</p>
            <hr style="border: none; border-top: 1px solid rgba(148, 163, 184, 0.1); margin: 24px 0;">
            <p style="color: #64748b; font-size: 12px; text-align: center;">If you didn't attempt to log in, please secure your account immediately.</p>
        </div>
        """
    }

    subject = subject_map.get(purpose, "Your OTP Code — Metadata Scanner")
    body = body_map.get(purpose, f"<p>Your OTP code is: <strong>{code}</strong></p>")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    # Add display name to the From address
    msg["From"] = f"Metadata Scanner <{mail_username}>"
    msg["To"] = to_email
    msg.attach(MIMEText(body, "html"))

    try:
        print(f"[OTP] Attempting to send email to {to_email} via {mail_server}:{mail_port}...")
        if mail_port == 465:
            with smtplib.SMTP_SSL(mail_server, mail_port) as server:
                server.set_debuglevel(0) # Set to 1 for even more detail in terminal
                server.login(mail_username, mail_password)
                server.sendmail(mail_username, to_email, msg.as_string())
        else:
            with smtplib.SMTP(mail_server, mail_port) as server:
                server.set_debuglevel(0) # Set to 1 for even more detail in terminal
                server.starttls()
                server.login(mail_username, mail_password)
                server.sendmail(mail_username, to_email, msg.as_string())
        
        print(f" {'='*60} ")
        print(f" [OTP] SUCCESS: Email sent to {to_email} ".center(60, "="))
        print(f" {'='*60} ")
        return True, None
    except smtplib.SMTPAuthenticationError:
        err = "Authentication Failed: Please use a 16-character Google App Password."
        print("\n" + "x"*60)
        print(" [OTP] SMTP AUTHENTICATION FAILED ".center(60, "x"))
        print(f" [OTP] User: {mail_username}")
        print(f" [OTP] Error: {err}")
        print(f" [OTP] Backup Code:  {code}")
        print("x"*60 + "\n")
        return False, err
    except Exception as e:
        err = f"SMTP Error: {e}"
        print("\n" + "?"*60)
        print(" [OTP] SMTP ERROR ".center(60, "?"))
        print(f" [OTP] Destination: {to_email}")
        print(f" [OTP] Technical details: {e}")
        print(f" [OTP] Backup Code:  {code}")
        print("?"*60 + "\n")
        return False, err
