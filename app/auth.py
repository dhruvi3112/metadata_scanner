from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db
from app.password_utils import is_strong_password
from app.otp_utils import generate_otp, store_otp, verify_otp, send_otp_email

auth = Blueprint("auth", __name__)

# ═══════════════════════════════════════════════════
#  REGISTER
# ═══════════════════════════════════════════════════
@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        raw_password = request.form["password"]

        valid, message = is_strong_password(raw_password)
        if not valid:
            return render_template("register.html", error=message)

        password = generate_password_hash(raw_password)

        db = get_db()
        try:
            role = "admin" if username == "Dhruvi" else "user"
            db.execute(
                "INSERT INTO users (username, email, password, role, email_verified) VALUES (?, ?, ?, ?, 1)",
                (username, email, password, role)
            )
            db.commit()

            flash("Account created! Please log in to receive your verification code.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            print(f"[Register] Error: {e}")
            return render_template("register.html", error="Username already exists")

    return render_template("register.html")


# EMAIL VERIFICATION REMOVED - NOW PART OF LOGIN 2FA


# ═══════════════════════════════════════════════════
#  LOGIN
# ═══════════════════════════════════════════════════
@auth.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("routes.dashboard"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            # Correct credentials -> send 2FA OTP
            code = generate_otp()
            store_otp(user["id"], code, "login_2fa")
            sent, smtp_error = send_otp_email(user["email"], code, "login_2fa")

            if not sent:
                flash(f"Note: Email delivery failed ({smtp_error or 'Unknown Error'}). For now, your code is printed to the terminal.", "warning")

            # Store pending 2FA session
            session["pending_2fa_user_id"] = user["id"]

            return redirect(url_for("auth.verify_2fa"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# ═══════════════════════════════════════════════════
#  TWO-FACTOR AUTHENTICATION
# ═══════════════════════════════════════════════════
@auth.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")

    if not user_id:
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        entered_code = request.form.get("otp", "").strip()

        if not entered_code:
            return render_template("verify_2fa.html", error="Please enter the verification code")

        valid, err_msg = verify_otp(user_id, entered_code, "login_2fa")
        if valid:
            # 2FA passed → create full session
            session.pop("pending_2fa_user_id", None)
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("routes.dashboard"))
        else:
            return render_template("verify_2fa.html", error=err_msg)

    # Mask the email for display
    email = user["email"]
    at_idx = email.index("@")
    masked = email[0:2] + "•" * (at_idx - 2) + email[at_idx:]

    return render_template("verify_2fa.html", masked_email=masked)


# ═══════════════════════════════════════════════════
#  RESEND OTP
# ═══════════════════════════════════════════════════
@auth.route("/resend-otp", methods=["POST"])
def resend_otp():
    purpose = request.form.get("purpose", "")

    # purpose is now always 'login_2fa' per user request to simplify
    if purpose == "login_2fa":
        user_id = session.get("pending_2fa_user_id")
        redirect_url = url_for("auth.verify_2fa")
        if user_id:
            db = get_db()
            user = db.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
            email = user["email"] if user else None
        else:
            email = None
    else:
        return redirect(url_for("auth.login"))

    if not user_id or not email:
        return redirect(url_for("auth.login"))

    code = generate_otp()
    store_otp(user_id, code, purpose)
    send_otp_email(email, code, purpose)

    # Flash a success message
    session["resend_success"] = "A new code has been sent to your email."
    return redirect(redirect_url)


# ═══════════════════════════════════════════════════
#  LOGOUT
# ═══════════════════════════════════════════════════
@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("routes.landing"))