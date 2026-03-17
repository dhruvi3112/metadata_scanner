from flask import Blueprint, render_template, request, send_from_directory, abort, flash
import os
from scanner.extractor import extract_metadata
from scanner.analyzer import analyze_metadata
from scanner.domain_scanner import scan_domain
from database import get_db
from reports.pdf_report import generate_pdf
from app.utils.risk_engine import calculate_risk
from app.utils.metadata_utils import find_leaked_metadata 
from app.security_utils import encrypt_data, decrypt_data
from functools import wraps
from flask import session, redirect, url_for, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash

routes = Blueprint("routes", __name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "generated_reports"
ALLOWED_EXTENSIONS = {"pdf", "docx"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


@routes.route("/ping")
def ping():
    return "Server is running"


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# ================= HOME PAGE =================
@routes.route("/", methods=["GET", "POST"])
def landing():
    from flask import session
    if "user_id" in session:
        return redirect(url_for("routes.dashboard"))
    return render_template("landing.html")

@routes.route("/dashboard")
@login_required
def dashboard():
    return render_template("index.html")

@routes.route("/scan", methods=["POST"])
@login_required
def scan_file():
    report_filename = None   # ✅ SAFE DEFAULT

    file = request.files.get("file")

    if not file or file.filename == "":
        return render_template("index.html", error="No file selected")

    if not allowed_file(file.filename):
        return render_template("index.html", error="Invalid file type")

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    metadata = extract_metadata(filepath)
    analysis = analyze_metadata(metadata)

    risk_score, risk_level = calculate_risk(metadata)
    analysis["risk_score"] = risk_score
    analysis["risk_level"] = risk_level

    scan_data = {
        "file_name": file.filename,
        "file_type": file.content_type,
        "metadata": metadata,
        "risk_score": risk_score,
        "risk_level": risk_level
    }
    report_path = generate_pdf(scan_data)
    if not report_path:
         return "PDF generation failed", 500
    report_filename = os.path.basename(report_path)

    db = get_db()
    
    # ENCRYPT filenames before saving to DB
    encrypted_filename = encrypt_data(file.filename)
    encrypted_report_filename = encrypt_data(report_filename)
    
    from database import IS_POSTGRES
    if IS_POSTGRES:
        cursor = db.execute(
            """
            INSERT INTO scan_history (user_id, filename, report_file, risk_score)
            VALUES (?, ?, ?, ?)
            RETURNING id
            """,
            (session["user_id"], encrypted_filename, encrypted_report_filename, risk_score)
        )
        scan_id = cursor.fetchone()["id"]
        db.commit()
    else:
        db.execute(
            """
            INSERT INTO scan_history (user_id, filename, report_file, risk_score)
            VALUES (?, ?, ?, ?)
            """,
            (session["user_id"], encrypted_filename, encrypted_report_filename, risk_score)
        )
        db.commit()
        scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    return render_template(
        "result.html",
        metadata=metadata,
        analysis=analysis,
        scan_id=scan_id     )

# ================= DOMAIN SCAN =================
@routes.route("/scan-domain", methods=["POST"])
def scan_domain_route():
    domain = request.form.get("domain")

    if not domain:
        return render_template("index.html", error="Please enter a domain")

    results = scan_domain(domain)

    return render_template(
        "domain_result.html",
        domain=domain,
        results=results
    )

@routes.route("/admin-only")
@login_required
@admin_required
def admin_area():
    return "Welcome Admin"

# ================= USER MANAGEMENT =================
@routes.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def manage_users():
    db = get_db()
    
    if request.method == "POST":
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        
        # Prevent admin from demoting themselves
        if str(user_id) == str(session.get("user_id")) and new_role != "admin":
            from flask import flash
            flash("You cannot demote yourself from admin.", "error")
        elif new_role in ["admin", "user"]:
            db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            db.commit()
            from flask import flash
            flash("User role updated successfully.", "success")
            
        return redirect(url_for("routes.manage_users"))

    users = db.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC").fetchall()
    return render_template("users.html", users=users)

# ================= SETTINGS =================
@routes.route("/admin/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings():
    db = get_db()
    if request.method == "POST":
        settings_data = {
            "MAIL_SERVER": request.form.get("mail_server"),
            "MAIL_PORT": request.form.get("mail_port"),
            "MAIL_USERNAME": request.form.get("mail_username"),
            "MAIL_PASSWORD": encrypt_data(request.form.get("mail_password"))
        }
        for key, value in settings_data.items():
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        db.commit()
        return render_template("settings.html", success="System settings updated successfully!", settings=settings_data)

    db_settings = db.execute("SELECT key, value FROM settings").fetchall()
    settings_dict = {row["key"]: row["value"] for row in db_settings}
    return render_template("settings.html", settings=settings_dict)

@routes.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        db = get_db()
        user = db.execute("SELECT password FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        
        if not check_password_hash(user["password"], current_password):
            return render_template("change_password.html", error="Incorrect current password")
            
        if new_password != confirm_password:
            return render_template("change_password.html", error="New passwords do not match")
            
        if len(new_password) < 8:
            return render_template("change_password.html", error="Password must be at least 8 characters long")
            
        hashed_password = generate_password_hash(new_password)
        db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, session["user_id"]))
        db.commit()
        
        return render_template("change_password.html", success="Password updated successfully!")
        
    return render_template("change_password.html")

# ================= HISTORY =================
@routes.route("/history")
@login_required
def history():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    db = get_db()

        scans_raw = db.execute(
            """
            SELECT scan_history.*, users.username
            FROM scan_history
            JOIN users ON scan_history.user_id = users.id
            ORDER BY created_at DESC
            """
        ).fetchall()
    else:
        scans_raw = db.execute(
            """
            SELECT *
            FROM scan_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (session["user_id"],)
        ).fetchall()

    # DECRYPT filenames for display
    scans = []
    for row in scans_raw:
        row_dict = dict(row)
        row_dict["filename"] = decrypt_data(row_dict.get("filename", ""))
        scans.append(row_dict)

    return render_template("history.html", scans=scans)


# ================= DOWNLOAD REPORT =================
@routes.route("/download/<int:scan_id>")
@login_required
def download_report(scan_id):
    db = get_db()

    if session.get("role") == "admin":
        scan = db.execute(
            "SELECT report_file FROM scan_history WHERE id = ?",
            (scan_id,)
        ).fetchone()
    else:
        scan = db.execute(
            """
            SELECT report_file FROM scan_history
            WHERE id = ? AND user_id = ?
            """,
            (scan_id, session["user_id"])
        ).fetchone()

    if not scan or not scan["report_file"]:
        abort(404)

    return send_from_directory(
        os.path.abspath("generated_reports"),
        scan["report_file"],
        as_attachment=True
    )