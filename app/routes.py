from flask import Blueprint, render_template, request, send_from_directory, abort, flash, session, redirect, url_for
import os
import datetime
from scanner.extractor import extract_metadata
from scanner.analyzer import analyze_metadata
from scanner.domain_scanner import scan_domain
from reports.pdf_report import generate_pdf
from app.utils.risk_engine import calculate_risk
from app.utils.metadata_utils import find_leaked_metadata 
from app.security_utils import encrypt_data, decrypt_data
from functools import wraps
from database import db
from firebase_admin import auth as admin_auth

routes = Blueprint("routes", __name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "generated_reports"
ALLOWED_EXTENSIONS = {"pdf", "docx"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

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
    report_filename = None

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

    encrypted_filename = encrypt_data(file.filename)
    encrypted_report_filename = encrypt_data(report_filename)
    
    # Store in Firestore
    scan_doc_ref = db.collection("scan_history").document()
    scan_doc_ref.set({
        "user_id": session["user_id"],
        "filename": encrypted_filename,
        "report_file": encrypted_report_filename,
        "risk_score": risk_score,
        "created_at": datetime.datetime.utcnow().isoformat()
    })
    
    scan_id = scan_doc_ref.id

    return render_template(
        "result.html",
        metadata=metadata,
        analysis=analysis,
        scan_id=scan_id
    )

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
    if request.method == "POST":
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        
        if str(user_id) == str(session.get("user_id")) and new_role != "admin":
            flash("You cannot demote yourself from admin.", "error")
        elif new_role in ["admin", "user"]:
            db.collection("users").document(user_id).update({"role": new_role})
            flash("User role updated successfully.", "success")
            
        return redirect(url_for("routes.manage_users"))

    users_docs = db.collection("users").stream()
    users = []
    for doc in users_docs:
        user_data = doc.to_dict()
        user_data["id"] = doc.id
        users.append(user_data)
        
    # Sort by created_at descending
    users.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return render_template("users.html", users=users)

# ================= SETTINGS =================
@routes.route("/admin/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings():
    if request.method == "POST":
        settings_data = {
            "MAIL_SERVER": request.form.get("mail_server"),
            "MAIL_PORT": request.form.get("mail_port"),
            "MAIL_USERNAME": request.form.get("mail_username"),
            "MAIL_PASSWORD": encrypt_data(request.form.get("mail_password"))
        }
        for key, value in settings_data.items():
            db.collection("settings").document(key).set({"value": value})
        
        # Reload dict for form display without encryption keys shown
        return render_template("settings.html", success="System settings updated successfully!", settings={k: v for k,v in settings_data.items() if k != "MAIL_PASSWORD"})

    settings_docs = db.collection("settings").stream()
    settings_dict = {doc.id: doc.to_dict().get("value") for doc in settings_docs}
    return render_template("settings.html", settings=settings_dict)

@routes.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        user_id = session.get("user_id")
        user_doc = db.collection("users").document(user_id).get().to_dict()
        email = user_doc.get("email")

        if new_password != confirm_password:
            return render_template("change_password.html", error="New passwords do not match")
            
        if len(new_password) < 8:
            return render_template("change_password.html", error="Password must be at least 8 characters long")
            
        try:
            from database import auth
            # Attempt signIn to verify current password
            auth.sign_in_with_email_and_password(email, current_password)
            
            # Update password with admin sdk
            admin_auth.update_user(user_id, password=new_password)
            return render_template("change_password.html", success="Password updated successfully!")
        except Exception as e:
            return render_template("change_password.html", error="Incorrect current password")
        
    return render_template("change_password.html")

# ================= HISTORY =================
@routes.route("/history")
@login_required
def history():
    if session.get("role") == "admin":
        scans_raw = []
        for scan_doc in db.collection("scan_history").stream():
            scan_dict = scan_doc.to_dict()
            scan_dict["id"] = scan_doc.id
            user_doc = db.collection("users").document(scan_dict.get("user_id")).get()
            if user_doc.exists:
                scan_dict["username"] = user_doc.to_dict().get("username")
            else:
                scan_dict["username"] = "Unknown"
            scans_raw.append(scan_dict)
    else:
        scans_raw = []
        for scan_doc in db.collection("scan_history").where("user_id", "==", session["user_id"]).stream():
            scan_dict = scan_doc.to_dict()
            scan_dict["id"] = scan_doc.id
            scans_raw.append(scan_dict)

    scans_raw.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    scans = []
    for row in scans_raw:
        row["filename"] = decrypt_data(row.get("filename", ""))
        scans.append(row)

    return render_template("history.html", scans=scans)


# ================= DOWNLOAD REPORT =================
@routes.route("/download/<scan_id>")
@login_required
def download_report(scan_id):
    scan_doc = db.collection("scan_history").document(scan_id).get()
    if not scan_doc.exists:
        abort(404)
        
    scan = scan_doc.to_dict()
    
    if session.get("role") != "admin" and scan.get("user_id") != session.get("user_id"):
        abort(403)

    if not scan.get("report_file"):
        abort(404)

    real_report_filename = decrypt_data(scan["report_file"])

    return send_from_directory(
        os.path.abspath("generated_reports"),
        real_report_filename,
        as_attachment=True
    )