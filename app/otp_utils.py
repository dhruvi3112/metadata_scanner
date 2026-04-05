import random
import string
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from database import db
from app.security_utils import decrypt_data

def generate_otp(length=6):
    """Generate a random numeric OTP code."""
    return ''.join(random.choices(string.digits, k=length))


def store_otp(user_id, code, purpose):
    """
    Store an OTP in the database with a 10-minute expiry.
    Invalidates any previous unused OTPs for the same user+purpose.
    purpose: 'login_2fa'
    """
    # Invalidate old unused OTPs for this user+purpose
    old_otps = db.collection('otp_codes').where('user_id', '==', user_id).where('purpose', '==', purpose).where('used', '==', 0).stream()
    for doc in old_otps:
        doc.reference.update({'used': 1})

    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    db.collection('otp_codes').add({
        'user_id': user_id,
        'code': code,
        'purpose': purpose,
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': expires_at.isoformat(),
        'used': 0
    })

def verify_otp(user_id, code, purpose):
    """
    Verify an OTP. Returns (True, None) on success or (False, error_message) on failure.
    Marks the OTP as used if valid.
    """
    otp_docs = db.collection('otp_codes').where('user_id', '==', user_id).where('code', '==', code).where('purpose', '==', purpose).where('used', '==', 0).stream()
    
    otp_docs_list = list(otp_docs)
    
    if not otp_docs_list:
        return False, "Invalid OTP code. Please try again."
        
    # Sort by created_at DESC
    otp_docs_list.sort(key=lambda x: x.to_dict().get('created_at', ''), reverse=True)
    latest_otp_doc = otp_docs_list[0]
    otp_data = latest_otp_doc.to_dict()

    raw_expires = otp_data["expires_at"]
    if isinstance(raw_expires, str):
        try:
            expires_at = datetime.fromisoformat(raw_expires)
            # Remove timezone info if it exists to compare with utcnow
            expires_at = expires_at.replace(tzinfo=None)
        except ValueError:
            try:
                expires_at = datetime.strptime(raw_expires, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                expires_at = datetime.strptime(raw_expires, "%Y-%m-%d %H:%M:%S")
    else:
        expires_at = raw_expires

    if datetime.utcnow() > expires_at:
        return False, "OTP has expired. Please request a new one."

    # Mark as used
    latest_otp_doc.reference.update({"used": 1})

    return True, None


def send_otp_email(to_email, code, purpose):
    """
    Send an OTP code via email using SMTP.
    Prioritizes DB settings, falls back to environment variables.
    Returns True on success, False on failure.
    """
    settings_docs = db.collection('settings').stream()
    settings_dict = {doc.id: doc.to_dict().get("value") for doc in settings_docs}

    mail_username = (settings_dict.get("MAIL_USERNAME") or os.environ.get("MAIL_USERNAME", "")).strip()
    encrypted_password = (settings_dict.get("MAIL_PASSWORD") or os.environ.get("MAIL_PASSWORD", "")).strip()
    
    # Check if empty string before decrypting
    mail_password = decrypt_data(encrypted_password) if encrypted_password else ""
    
    mail_server = (settings_dict.get("MAIL_SERVER") or os.environ.get("MAIL_SERVER", "smtp.gmail.com")).strip()
    mail_port_str = (settings_dict.get("MAIL_PORT") or os.environ.get("MAIL_PORT", "587")).strip()
    try:
        mail_port = int(mail_port_str)
    except:
        mail_port = 587

    len_pw = len(mail_password) if mail_password else 0
    print(f"[OTP] SMTP Config: server={mail_server}, port={mail_port}, user={mail_username}, pw_len={len_pw}")
    if not mail_username or len_pw == 0:
        print("\n" + "!"*60)
        print(" [OTP] WARNING: SMTP CONFIGURATION MISSING ".center(60, "!"))
        print(f" [OTP] Please configure SMTP settings in the Admin Dashboard.")
        print(f" [OTP] Or set MAIL_USERNAME and MAIL_PASSWORD env vars.")
        print(f" [OTP] Destination: {to_email}")
        print(f" [OTP] Code:        {code}")
        print(f" [OTP] Purpose:     {purpose}")
        print("!"*60 + "\n")
        return False, "SMTP not configured. Set MAIL_USERNAME and MAIL_PASSWORD."

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
    msg["From"] = f"Metadata Scanner <{mail_username}>"
    msg["To"] = to_email
    msg.attach(MIMEText(body, "html"))

    try:
        if mail_port == 465:
            server_class = smtplib.SMTP_SSL
        else:
            server_class = smtplib.SMTP

        with server_class(mail_server, mail_port, timeout=15) as server:
            server.set_debuglevel(0)
            if mail_port != 465:
                server.starttls()
            server.login(mail_username, mail_password)
            server.sendmail(mail_username, to_email, msg.as_string())
        
        return True, None
    except smtplib.SMTPAuthenticationError:
        err = "Authentication Failed: Please use a 16-character Google App Password."
        return False, err
    except Exception as e:
        err = f"SMTP Error: {e}"
        return False, err
