from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory
from config import get_db_connection # type: ignore
from collections import defaultdict
from datetime import datetime
import mysql.connector
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = "replace_this_with_a_random_secret_key"

# ==========================
# SECURITY + CONFIG
# ==========================
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # enable only in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ==========================
# UPLOAD SETTINGS
# ==========================
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "avi", "mov", "mkv"}


def allowed_file(filename, allowed_set):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set


# ==========================
# Serve uploaded files
# ==========================
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ==========================
# INDEX / LOGIN / REGISTER
# ==========================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["user_id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            flash("⚠️ Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/agency-login", methods=["GET", "POST"])
def agency_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and user["role"] in ("BFP", "PNP", "CDRRMO"):
            if check_password_hash(user["password"], password):
                session["user_id"] = user["user_id"]
                session["name"] = user["name"]
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))
            else:
                flash("⚠️ Incorrect password.", "error")
        else:
            flash("🚫 Invalid agency credentials.", "error")

    return render_template("agency_login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form.get("confirm_password", "")
        contact_no = request.form["contact_no"].strip()
        role = "Public"

        # validations...
        if not all([name, email, password, contact_no]):
            flash("⚠️ All fields required.", "error")
            return redirect(url_for("register"))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("⚠️ Invalid email.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("⚠️ Passwords do not match.", "error")
            return redirect(url_for("register"))

        if len(password) < 8 or not re.search(r"[A-Z]", password):
            flash("⚠️ Weak password.", "error")
            return redirect(url_for("register"))

        if not re.match(r"^09\d{9}$", contact_no):
            flash("⚠️ Invalid contact number.", "error")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing = cur.fetchone()

        if existing:
            flash("⚠️ Email already registered.", "error")
            return redirect(url_for("login"))

        hashed_pw = generate_password_hash(password)
        cur.execute("""
            INSERT INTO users (name, email, password, contact_no, role)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, hashed_pw, contact_no, role))
        conn.commit()
        cur.close()
        conn.close()

        flash("✅ Registration successful!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ==========================
# REPORT INCIDENT
# ==========================
@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session or session["role"] != "Public":
        flash("You must be logged in as a public user.")
        return redirect(url_for("login"))

    if request.method == "POST":
        incident_type = request.form["incident_type"]
        description = request.form["description"]
        location = request.form["location"]
        gps_lat = request.form.get("gps_lat") or None
        gps_long = request.form.get("gps_long") or None
        agencies = request.form.getlist("agencies")
        agencies_text = ",".join(agencies) if agencies else None

        # ✅ Upload handling
        image_file = request.files.get("incident_image")
        video_file = request.files.get("incident_video")
        image_filename = None
        video_filename = None

        if image_file and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        if video_file and allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS):
            filename = secure_filename(video_file.filename)
            video_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            video_filename = filename

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO incidents (reported_by_user_id, incident_type, description, location,
                                   gps_lat, gps_long, status, date_reported, agencies_notified, image_path, video_path)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"], incident_type, description, location,
            gps_lat, gps_long, "Pending", datetime.now(),
            agencies_text, image_filename, video_filename
        ))
        incident_id = cur.lastrowid

        # ✅ record to incident_history
        cur.execute("""
            INSERT INTO incident_history (incident_id, updated_by, status_update, notes)
            VALUES (%s, %s, %s, %s)
        """, (incident_id, session["user_id"], "Pending", "Initial report submitted"))

        # ✅ store media info
        if image_filename:
            cur.execute("""
                INSERT INTO media (incident_id, file_path, file_type)
                VALUES (%s, %s, 'image')
            """, (incident_id, image_filename))
        if video_filename:
            cur.execute("""
                INSERT INTO media (incident_id, file_path, file_type)
                VALUES (%s, %s, 'video')
            """, (incident_id, video_filename))

        conn.commit()
        cur.close()
        conn.close()

        flash("✅ Incident reported successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("report.html")


# ==========================
# INCIDENTS LIST
# ==========================
@app.route("/incidents")
def incidents():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session["role"]
    user_id = session["user_id"]
    filter_status = request.args.get("status")

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    if role == "Public":
        query = """
            SELECT i.*, u.name AS reported_by
            FROM incidents i
            JOIN users u ON i.reported_by_user_id = u.user_id
            WHERE i.reported_by_user_id = %s
        """
        params = [user_id]
        if filter_status:
            query += " AND i.status = %s"
            params.append(filter_status)
    else:
        query = """
            SELECT i.*, u.name AS reported_by
            FROM incidents i
            JOIN users u ON i.reported_by_user_id = u.user_id
        """
        params = []
        if role != "Admin":
            query += " WHERE i.agencies_notified LIKE %s"
            params.append(f"%{role}%")
        if filter_status:
            query += " AND i.status = %s" if params else " WHERE i.status = %s"
            params.append(filter_status)

    query += " ORDER BY i.date_reported DESC"
    cur.execute(query, tuple(params))
    incidents = cur.fetchall()
    cur.close()
    conn.close()

    grouped = defaultdict(list)
    for inc in incidents:
        try:
            date = datetime.strptime(str(inc["date_reported"]), "%Y-%m-%d %H:%M:%S")
            label = date.strftime("%B %Y")
        except:
            label = "Unknown Date"
        grouped[label].append(inc)
    grouped_sorted = dict(sorted(grouped.items(), reverse=True))

    return render_template("incidents.html", incidents_by_month=grouped_sorted, role=role)


# ==========================
# UPDATE STATUS (AGENCY)
# ==========================
@app.route("/update_status/<int:incident_id>", methods=["POST"])
def update_status(incident_id):
    if "user_id" not in session or session["role"] not in ("BFP", "PNP", "CDRRMO"):
        return "Access denied", 403

    new_status = request.form.get("status")
    if new_status not in ("Pending", "Verified", "Resolved"):
        return "Invalid status", 400

    conn = get_db_connection()
    cur = conn.cursor()

    # update incident status
    cur.execute("UPDATE incidents SET status=%s WHERE incident_id=%s", (new_status, incident_id))

    # record in history
    cur.execute("""
        INSERT INTO incident_history (incident_id, updated_by, status_update, notes)
        VALUES (%s, %s, %s, %s)
    """, (incident_id, session["user_id"], new_status, f"Status changed to {new_status}"))

    # create alert
    cur.execute("""
        INSERT INTO alerts (incident_id, recipient_id, message, status)
        VALUES (%s, %s, %s, 'Pending')
    """, (incident_id, session["user_id"], f"Incident #{incident_id} updated to {new_status}"))

    conn.commit()
    cur.close()
    conn.close()

    flash(f"Incident #{incident_id} updated to {new_status}.", "success")
    return redirect(url_for("incidents"))


# ==========================
# DASHBOARD
# ==========================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", name=session["name"], role=session["role"])


# ==========================
# LOGOUT
# ==========================
@app.route("/logout")
def logout():
    role = session.get("role")
    session.clear()
    if role in ("BFP", "PNP", "CDRRMO"):
        return redirect(url_for("agency_login"))
    return redirect(url_for("login"))


# ==========================
# RUN APP
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
