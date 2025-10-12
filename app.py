from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from collections import defaultdict
import os
import re

app = Flask(__name__)
app.secret_key = "replace_this_with_a_random_secret_key"

# 🔒 Security configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # enable in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Upload folder config
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "avi", "mov", "mkv"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------------------
# DATABASE CONFIGURATION
# ---------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+mysqlconnector://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASS')}"
    f"@{os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT')}/{os.environ.get('DB_NAME')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------------------
# DATABASE MODELS
# ---------------------------
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    contact_no = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), default="Public", nullable=False)

class Incident(db.Model):
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    reported_by_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    incident_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    gps_lat = db.Column(db.Float)
    gps_long = db.Column(db.Float)
    status = db.Column(db.String(50), default="Pending")
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    agencies_notified = db.Column(db.String(255))
    image_path = db.Column(db.String(255))
    video_path = db.Column(db.String(255))

# Create tables if not exist
with app.app_context():
    db.create_all()

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------
def allowed_file(filename, allowed_set):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set

# ---------------------------
# ROUTES
# ---------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# ---------------------------
# LOGIN
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.user_id
            session["name"] = user.name
            session["role"] = user.role
            return redirect(url_for("dashboard"))
        else:
            flash("⚠️ Invalid email or password. Please try again.", "error")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/agency-login", methods=["GET", "POST"])
def agency_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and user.role in ("BFP", "PNP", "CDRRMO") and check_password_hash(user.password, password):
            session["user_id"] = user.user_id
            session["name"] = user.name
            session["role"] = user.role
            return redirect(url_for("dashboard"))
        else:
            flash("🚫 Invalid agency credentials or password.", "error")
    return render_template("agency_login.html")

# ---------------------------
# REGISTER
# ---------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form.get("confirm_password", "")
        contact_no = request.form["contact_no"].strip()
        role = "Public"

        # Validations
        if not name or not email or not password or not contact_no:
            flash("⚠️ All fields are required.", "error")
            return redirect(url_for("register"))
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("⚠️ Invalid email format.", "error")
            return redirect(url_for("register"))
        if password != confirm_password:
            flash("⚠️ Passwords do not match.", "error")
            return redirect(url_for("register"))
        if len(password) < 8 or not re.search(r"[A-Z]", password) \
           or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) \
           or not re.search(r"[@$!%*?&]", password):
            flash("⚠️ Password must have 8+ chars, uppercase, lowercase, number, and special symbol.", "error")
            return redirect(url_for("register"))
        if not re.match(r"^09\d{9}$", contact_no):
            flash("⚠️ Invalid contact number. Use 09XXXXXXXXX format.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("⚠️ Email already registered. Please log in.", "error")
            return redirect(url_for("login"))

        hashed_pw = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_pw, contact_no=contact_no, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

# ---------------------------
# REPORT INCIDENT
# ---------------------------
@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session or session["role"] != "Public":
        flash("You must be logged in as a public user to report an incident.")
        return redirect(url_for("login"))

    if request.method == "POST":
        incident_type = request.form["incident_type"]
        description = request.form["description"]
        location = request.form["location"]
        gps_lat = request.form.get("gps_lat") or None
        gps_long = request.form.get("gps_long") or None
        selected_agencies = request.form.getlist("agencies")
        agencies_text = ",".join(selected_agencies) if selected_agencies else None

        image_file = request.files.get("incident_image")
        image_filename = None
        if image_file and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        video_file = request.files.get("incident_video")
        video_filename = None
        if video_file and allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS):
            filename = secure_filename(video_file.filename)
            video_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            video_filename = filename

        new_incident = Incident(
            reported_by_user_id=session["user_id"],
            incident_type=incident_type,
            description=description,
            location=location,
            gps_lat=float(gps_lat) if gps_lat else None,
            gps_long=float(gps_long) if gps_long else None,
            status="Pending",
            date_reported=datetime.now(),
            agencies_notified=agencies_text,
            image_path=image_filename,
            video_path=video_filename
        )
        db.session.add(new_incident)
        db.session.commit()

        flash(f"Incident reported successfully to: {agencies_text if agencies_text else 'No agency selected.'}")
        return redirect(url_for("dashboard"))

    return render_template("report.html")

# ---------------------------
# VIEW INCIDENTS
# ---------------------------
@app.route("/incidents")
def incidents():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session["role"]
    user_id = session["user_id"]
    filter_status = request.args.get("status")

    if role == "Public":
        query = Incident.query.filter_by(reported_by_user_id=user_id)
        if filter_status:
            query = query.filter_by(status=filter_status)
    else:
        query = Incident.query
        if role != "Admin":
            query = query.filter(Incident.agencies_notified.like(f"%{role}%"))
        if filter_status:
            query = query.filter_by(status=filter_status)

    all_incidents = query.order_by(Incident.date_reported.desc()).all()

    grouped = defaultdict(list)
    for inc in all_incidents:
        month_label = inc.date_reported.strftime("%B %Y") if inc.date_reported else "Unknown Date"
        grouped[month_label].append(inc)

    grouped_sorted = dict(sorted(grouped.items(), reverse=True))
    return render_template("incidents.html", incidents_by_month=grouped_sorted, role=role)

# ---------------------------
# DASHBOARD
# ---------------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", name=session["name"], role=session["role"])

# ---------------------------
# UPDATE STATUS
# ---------------------------
@app.route("/update_status/<int:incident_id>", methods=["POST"])
def update_status(incident_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] not in ("BFP", "PNP", "CDRRMO"):
        return "Access denied", 403

    new_status = request.form.get("status")
    if new_status not in ("Pending", "Verified", "Resolved"):
        return "Invalid status", 400

    incident = Incident.query.get(incident_id)
    if incident:
        incident.status = new_status
        db.session.commit()

    flash(f"Incident {incident_id} status updated to {new_status}.")
    return redirect(url_for("incidents"))

# ---------------------------
# API: NEW INCIDENTS
# ---------------------------
@app.route("/api/new_incidents")
def api_new_incidents():
    if "user_id" not in session:
        return jsonify({"error": "login required"}), 401

    role = session.get("role")
    since_param = request.args.get("since", "0")
    try:
        since = float(since_param)
    except ValueError:
        since = 0.0

    if role == "Admin":
        incidents = Incident.query.filter(db.func.UNIX_TIMESTAMP(Incident.date_reported) > since).all()
    else:
        incidents = Incident.query.filter(
            db.func.UNIX_TIMESTAMP(Incident.date_reported) > since,
            Incident.agencies_notified.like(f"%{role}%")
        ).all()

    result = []
    for inc in incidents:
        user = User.query.get(inc.reported_by_user_id)
        result.append({
            "incident_id": inc.incident_id,
            "incident_type": inc.incident_type,
            "description": inc.description,
            "location": inc.location,
            "gps_lat": inc.gps_lat,
            "gps_long": inc.gps_long,
            "status": inc.status,
            "ts": int(inc.date_reported.timestamp()),
            "agencies_notified": inc.agencies_notified,
            "reported_by": user.name if user else "Unknown"
        })
    return jsonify(result)

# ---------------------------
# INCIDENT DETAIL
# ---------------------------
@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    incident = Incident.query.get(incident_id)
    user = User.query.get(incident.reported_by_user_id) if incident else None

    if not incident:
        return "Incident not found", 404

    return render_template("incident_detail.html", incident=incident, reporter=user)

# ---------------------------
# LOGOUT
# ---------------------------
@app.route("/logout")
def logout():
    role = session.get("role")
    session.clear()
    if role in ("BFP", "PNP", "CDRRMO"):
        return redirect(url_for("agency_login"))
    return redirect(url_for("login"))

# ---------------------------
# RUN APP
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
