from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from database import auth, db
from app.password_utils import is_strong_password
from app.otp_utils import generate_otp, store_otp, verify_otp, send_otp_email
import datetime

auth_bp = Blueprint("auth", __name__)

# ═══════════════════════════════════════════════════
#  REGISTER
# ═══════════════════════════════════════════════════
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        raw_password = request.form["password"]

        valid, message = is_strong_password(raw_password)
        if not valid:
            return render_template("register.html", error=message)

        # Check if username already exists in Firestore
        docs = db.collection("users").where("username", "==", username).stream()
        if any(docs):
            return render_template("register.html", error="Username already exists")

        try:
            # Create user in Firebase Auth
            user = auth.create_user_with_email_and_password(email, raw_password)
            user_id = user["localId"]
            
            # Save additional user metadata in Firestore
            role = "admin" if username == "Dhruvi" else "user"
            db.collection("users").document(user_id).set({
                "username": username,
                "email": email,
                "role": role,
                "email_verified": True,
                "created_at": datetime.datetime.utcnow().isoformat()
            })

            flash("Account created! Please log in to receive your verification code.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            print(f"[Register] Error: {e}")
            error_msg = str(e)
            if "EMAIL_EXISTS" in error_msg:
                return render_template("register.html", error="Email already in use.")
            elif "OPERATION_NOT_ALLOWED" in error_msg:
                return render_template("register.html", error="Error: Firebase Email/Password Auth is disabled in your console.")
            else:
                # Often Pyrebase throws a complex JSON error, let's catch standard text
                return render_template("register.html", error=f"Registration failed. {error_msg[:100]}")

    return render_template("register.html")


# ═══════════════════════════════════════════════════
#  LOGIN
# ═══════════════════════════════════════════════════
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("routes.dashboard"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        try:
            # Look up email by username in Firestore
            docs = list(db.collection("users").where("username", "==", username).stream())
            if not docs:
                return render_template("login.html", error="Invalid credentials")

            user_doc = docs[0]
            user_data = user_doc.to_dict()
            email = user_data.get("email")

            # Authenticate with Firebase Auth
            login_user = auth.sign_in_with_email_and_password(email, password)
            user_id = login_user["localId"]

            # Store OTP logic is kept (2FA)
            code = generate_otp()
            store_otp(user_id, code, "login_2fa")
            sent, smtp_error = send_otp_email(email, code, "login_2fa")

            if not sent:
                print(f"[Login] SMTP failed: {smtp_error}")
                flash(f"Email delivery failed. Your emergency login code is: {code}", "warning")

            # Store pending 2FA session
            session["pending_2fa_user_id"] = user_id

            return redirect(url_for("auth.verify_2fa"))

        except Exception as e:
            print(f"[Login] Error: {e}")
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# ═══════════════════════════════════════════════════
#  TWO-FACTOR AUTHENTICATION
# ═══════════════════════════════════════════════════
@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")

    if not user_id:
        return redirect(url_for("auth.login"))

    user_ref = db.collection("users").document(user_id).get()
    if not user_ref.exists:
        return redirect(url_for("auth.login"))
        
    user_data = user_ref.to_dict()

    if request.method == "POST":
        entered_code = request.form.get("otp", "").strip()

        if not entered_code:
            return render_template("verify_2fa.html", error="Please enter the verification code")

        valid, err_msg = verify_otp(user_id, entered_code, "login_2fa")
        if valid:
            session.pop("pending_2fa_user_id", None)
            session["user_id"] = user_id
            session["username"] = user_data["username"]
            session["role"] = user_data.get("role", "user")
            return redirect(url_for("routes.dashboard"))
        else:
            return render_template("verify_2fa.html", error=err_msg)

    email = user_data["email"]
    try:
        at_idx = email.index("@")
        masked = email[0:2] + "•" * (at_idx - 2) + email[at_idx:]
    except ValueError:
        masked = email

    return render_template("verify_2fa.html", masked_email=masked)


# ═══════════════════════════════════════════════════
#  RESEND OTP
# ═══════════════════════════════════════════════════
@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    purpose = request.form.get("purpose", "")
    if purpose == "login_2fa":
        user_id = session.get("pending_2fa_user_id")
        redirect_url = url_for("auth.verify_2fa")
        if user_id:
            user_ref = db.collection("users").document(user_id).get()
            email = user_ref.to_dict().get("email") if user_ref.exists else None
        else:
            email = None
    else:
        return redirect(url_for("auth.login"))

    if not user_id or not email:
        return redirect(url_for("auth.login"))

    code = generate_otp()
    store_otp(user_id, code, purpose)
    send_otp_email(email, code, purpose)

    session["resend_success"] = "A new code has been sent to your email."
    return redirect(redirect_url)


# ═══════════════════════════════════════════════════
#  LOGOUT
# ═══════════════════════════════════════════════════
@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("routes.landing"))