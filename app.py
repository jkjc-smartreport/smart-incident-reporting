from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory
from config import get_db_connection  # type: ignore
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import mysql.connector
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = "replace_this_with_a_random_secret_key"  # needed for sessions

# 🔒 Security configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True    # Enable only in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ==========================
# PERSISTENT UPLOAD FOLDER (Render-ready)
# ==========================
# Use a folder inside your app root so Flask can write files
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "avi", "mov", "mkv"}

# PH time zone (UTC+8)
PH_TIMEZONE = timezone(timedelta(hours=8))

# Helper function to check valid file extensions
def allowed_file(filename, allowed_set):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set

# ==========================
# Serve uploaded files
# ==========================
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ==========================
# Routes
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
            flash("⚠️ Invalid email or password. Please try again.", "error")
            return render_template("login.html")

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
                flash("⚠️ Incorrect password. Please try again.", "error")
        else:
            flash("🚫 Invalid agency credentials or not authorized.", "error")

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
            flash("⚠️ Password must have 8+ characters, uppercase, lowercase, number, and special symbol.", "error")
            return redirect(url_for("register"))

        if not re.match(r"^09\d{9}$", contact_no):
            flash("⚠️ Invalid contact number. Use 09XXXXXXXXX format.", "error")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing = cur.fetchone()
        if existing:
            flash("⚠️ This email is already registered. Please log in instead.", "error")
            cur.close()
            conn.close()
            return redirect(url_for("login"))

        hashed_pw = generate_password_hash(password)
        cur.execute("""
            INSERT INTO users (name, email, password, contact_no, role)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, hashed_pw, contact_no, role))
        conn.commit()
        cur.close()
        conn.close()

        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ==========================
# REPORT INCIDENT
# ==========================
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

        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Insert into incidents
        cur.execute("""
            INSERT INTO incidents 
            (reported_by_user_id, incident_type, description, location, gps_lat, gps_long,
             status, date_reported, agencies_notified, image_path, video_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session["user_id"], incident_type, description, location, gps_lat, gps_long,
            "Pending", datetime.now(PH_TIMEZONE), agencies_text, image_filename, video_filename
        ))
        incident_id = cur.lastrowid

        # ✅ Log to incident_history table
        cur.execute("""
            INSERT INTO incident_history (incident_id, updated_by, status_update, notes)
            VALUES (%s, %s, %s, %s)
        """, (incident_id, session["user_id"], "Pending", "New incident reported."))

        # ✅ Save uploaded files to media table
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

        # ✅ Send alerts to agencies
        if agencies_text:
            for agency in selected_agencies:
                cur.execute("""
                    INSERT INTO alerts (incident_id, message, status)
                    VALUES (%s, %s, 'Pending')
                """, (incident_id, f"New {incident_type} reported in {location}"))

        conn.commit()
        cur.close()
        conn.close()

        flash(f"Incident reported successfully to: {agencies_text if agencies_text else 'No agency selected.'}")
        return redirect(url_for("dashboard"))

    return render_template("report.html")

# ==========================
# INCIDENT LIST
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
            SELECT i.incident_id, i.incident_type, i.description, i.location,
                   i.gps_lat, i.gps_long, i.status, i.date_reported,
                   i.agencies_notified, i.image_path, i.video_path,
                   u.name AS reported_by
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
            SELECT i.incident_id, i.incident_type, i.description, i.location,
                   i.gps_lat, i.gps_long, i.status, i.date_reported,
                   i.agencies_notified, i.image_path, i.video_path,
                   u.name AS reported_by
            FROM incidents i
            JOIN users u ON i.reported_by_user_id = u.user_id
        """
        params = []
        if role != "Admin":
            query += " WHERE i.agencies_notified LIKE %s"
            params.append(f"%{role}%")
        if filter_status:
            if role == "Admin":
                query += " WHERE"
            else:
                query += " AND"
            query += " i.status = %s"
            params.append(filter_status)

    query += " ORDER BY i.date_reported DESC"
    cur.execute(query, tuple(params))
    all_incidents = cur.fetchall()
    cur.close()
    conn.close()

    grouped = defaultdict(list)
    for inc in all_incidents:
        if isinstance(inc["date_reported"], datetime):
            local_time = inc["date_reported"].astimezone(PH_TIMEZONE)
            month_label = local_time.strftime("%B %Y")
        else:
            month_label = "Unknown Date"
        grouped[month_label].append(inc)

    grouped_sorted = dict(sorted(grouped.items(), reverse=True))

    return render_template("incidents.html", incidents_by_month=grouped_sorted, role=role)

# ==========================
# DASHBOARD
# ==========================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", name=session["name"], role=session["role"])

# ==========================
# UPDATE INCIDENT STATUS
# ==========================
@app.route("/update_status/<int:incident_id>", methods=["POST"])
def update_status(incident_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] not in ("BFP", "PNP", "CDRRMO"):
        return "Access denied", 403

    new_status = request.form.get("status")
    if new_status not in ("Pending", "Verified", "Resolved"):
        return "Invalid status", 400

    conn = get_db_connection()
    cur = conn.cursor()

    # ✅ Update incident
    cur.execute("UPDATE incidents SET status=%s WHERE incident_id=%s", (new_status, incident_id))

    # ✅ Record in history
    cur.execute("""
        INSERT INTO incident_history (incident_id, updated_by, status_update, notes)
        VALUES (%s, %s, %s, %s)
    """, (incident_id, session["user_id"], new_status, f"Status changed to {new_status}"))

    # ✅ Send alert notification
    cur.execute("""
        INSERT INTO alerts (incident_id, message, status)
        VALUES (%s, %s, 'Pending')
    """, (incident_id, f"Incident {incident_id} status updated to {new_status}"))

    conn.commit()
    cur.close()
    conn.close()

    flash(f"Incident {incident_id} status updated to {new_status}.")
    return redirect(url_for("incidents"))

# ==========================
# API: NEW INCIDENTS
# ==========================
@app.route("/api/new_incidents")
def api_new_incidents():
    if "user_id" not in session:
        return jsonify({"error": "login required"}), 401

    role = session.get("role")
    since = float(request.args.get("since", 0))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    if role == "Admin":
        cur.execute("""
            SELECT i.incident_id, i.incident_type, i.description, i.location,
                   i.gps_lat, i.gps_long, i.status, UNIX_TIMESTAMP(i.date_reported) AS ts,
                   i.agencies_notified, u.name AS reported_by
            FROM incidents i
            JOIN users u ON i.reported_by_user_id = u.user_id
            WHERE UNIX_TIMESTAMP(i.date_reported) > %s
            ORDER BY i.date_reported ASC
        """, (since,))
    else:
        cur.execute("""
            SELECT i.incident_id, i.incident_type, i.description, i.location,
                   i.gps_lat, i.gps_long, i.status, UNIX_TIMESTAMP(i.date_reported) AS ts,
                   i.agencies_notified, u.name AS reported_by
            FROM incidents i
            JOIN users u ON i.reported_by_user_id = u.user_id
            WHERE UNIX_TIMESTAMP(i.date_reported) > %s
              AND i.agencies_notified LIKE %s
            ORDER BY i.date_reported ASC
        """, (since, f"%{role}%"))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    if rows:
        # ✅ Save the most recent timestamp seen
        latest_ts = max(row["ts"] for row in rows)
        session["last_seen_incident_ts"] = latest_ts

    return jsonify(rows)

# ==========================
# INCIDENT DETAIL
# ==========================
@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT i.*, u.name AS reported_by, u.contact_no
        FROM incidents i
        JOIN users u ON i.reported_by_user_id = u.user_id
        WHERE i.incident_id = %s
    """, (incident_id,))
    incident = cur.fetchone()
    cur.close()
    conn.close()

    if not incident:
        return "Incident not found", 404

    return render_template("incident_detail.html", incident=incident)

@app.route("/delete_incident/<int:incident_id>", methods=["POST"])
def delete_incident(incident_id):
    if "user_id" not in session or session["role"] != "Public":
        return "Access denied", 403

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    # Delete media files
    cur.execute("DELETE FROM media WHERE incident_id=%s", (incident_id,))

    # Delete history
    cur.execute("DELETE FROM incident_history WHERE incident_id=%s", (incident_id,))

    # Delete alerts
    cur.execute("DELETE FROM alerts WHERE incident_id=%s", (incident_id,))

    # Delete the main incident (only if belongs to this public user AND still pending)
    cur.execute("""
        DELETE FROM incidents 
        WHERE incident_id=%s AND reported_by_user_id=%s AND status='Pending'
    """, (incident_id, user_id))

    conn.commit()
    cur.close()
    conn.close()

    flash("✅ Incident deleted successfully.", "success")
    return redirect(url_for("incidents"))


# ==========================
# LOGOUT
# ==========================
@app.route("/logout")
def logout():
    role = session.get("role")
    session.clear()
    if role in ("BFP", "PNP", "CDRRMO"):
        return redirect(url_for("agency_login"))
    else:
        return redirect(url_for("login"))
    
@app.route("/api/dismiss_alerts", methods=["POST"])
def dismiss_alerts():
    session["last_seen_incident_ts"] = datetime.now().timestamp()
    return jsonify({"status": "ok"})

@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ==========================
# RUN APP
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
