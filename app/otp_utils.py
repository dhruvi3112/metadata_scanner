import random
import string
import smtplib
import os
import requests
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


def _get_email_html(code, purpose):
    """Generate the HTML email body for OTP emails."""
    if purpose == "email_verify":
        return f"""
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
        """
    else:
        return f"""
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


def _send_via_resend(to_email, subject, html_body, from_email):
    """Send email via Resend HTTP API (works on Render/free hosting)."""
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        return False, "RESEND_API_KEY not set"

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "from": f"Metadata Scanner <{from_email}>",
                "to": [to_email],
                "subject": subject,
                "html": html_body
            },
            timeout=15
        )
        if resp.status_code in (200, 201, 202):
            print(f"[OTP] Resend: Email sent successfully to {to_email}")
            return True, None
        else:
            err = f"Resend API error {resp.status_code}: {resp.text}"
            print(f"[OTP] {err}")
            return False, err
    except Exception as e:
        err = f"Resend error: {e}"
        print(f"[OTP] {err}")
        return False, err


def _send_via_brevo(to_email, subject, html_body, from_email):
    """Send email via Brevo HTTP API (works on Render, no domain verification required)."""
    api_key = os.environ.get("BREVO_API_KEY", "")
    if not api_key:
        return False, "BREVO_API_KEY not set"

    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
                "accept": "application/json"
            },
            json={
                "sender": {"name": "Metadata Scanner", "email": from_email},
                "to": [{"email": to_email}],
                "subject": subject,
                "htmlContent": html_body
            },
            timeout=15
        )
        if resp.status_code in (200, 201, 202, 204):
            print(f"[OTP] Brevo: Email sent successfully to {to_email}")
            return True, None
        else:
            err = f"Brevo API error {resp.status_code}: {resp.text}"
            print(f"[OTP] {err}")
            return False, err
    except Exception as e:
        err = f"Brevo error: {e}"
        print(f"[OTP] {err}")
        return False, err



def _send_via_smtp(to_email, subject, html_body, mail_username, mail_password, mail_server, mail_port):
    """Send email via SMTP (works for local development)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Metadata Scanner <{mail_username}>"
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

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
        
        print(f"[OTP] SMTP: Email sent successfully to {to_email}")
        return True, None
    except smtplib.SMTPAuthenticationError:
        err = "Authentication Failed: Please use a 16-character Google App Password."
        return False, err
    except Exception as e:
        err = f"SMTP Error: {e}"
        return False, err


def send_otp_email(to_email, code, purpose):
    """
    Send an OTP code via email.
    Uses Resend HTTP API first (for cloud hosting like Render),
    falls back to SMTP (for local development).
    Returns (success, error_message).
    """
    subject_map = {
        "email_verify": "Verify Your Email — Metadata Scanner",
        "login_2fa": "Your Login Verification Code — Metadata Scanner"
    }
    subject = subject_map.get(purpose, "Your OTP Code — Metadata Scanner")
    html_body = _get_email_html(code, purpose)

    # ── Method 1: Brevo HTTP API (Best for Render, no domain needed) ──
    brevo_api_key = os.environ.get("BREVO_API_KEY", "")
    if brevo_api_key:
        print(f"[OTP] Using Brevo API to send email to {to_email}")
        from_email = os.environ.get("MAIL_USERNAME", "noreply@metadatascanner.com")
        return _send_via_brevo(to_email, subject, html_body, from_email)

    # ── Method 2: Resend HTTP API (works on Render, requires verified domain) ──
    resend_api_key = os.environ.get("RESEND_API_KEY", "")
    resend_from = os.environ.get("RESEND_FROM_EMAIL", "onboarding@resend.dev")
    if resend_api_key:
        print(f"[OTP] Using Resend API to send email to {to_email}")
        return _send_via_resend(to_email, subject, html_body, resend_from)

    # ── Method 2: SMTP (works for local dev) ──
    settings_docs = db.collection('settings').stream()
    settings_dict = {doc.id: doc.to_dict().get("value") for doc in settings_docs}

    mail_username = (settings_dict.get("MAIL_USERNAME") or os.environ.get("MAIL_USERNAME", "")).strip()
    encrypted_password = (settings_dict.get("MAIL_PASSWORD") or os.environ.get("MAIL_PASSWORD", "")).strip()
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
        print("[OTP] WARNING: No email method configured!")
        print("[OTP] Set RESEND_API_KEY for cloud hosting, or MAIL_USERNAME + MAIL_PASSWORD for SMTP.")
        return False, "No email service configured. Set RESEND_API_KEY or SMTP credentials."

    return _send_via_smtp(to_email, subject, html_body, mail_username, mail_password, mail_server, mail_port)

