from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify, abort, make_response, g
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, TextAreaField, SelectField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Email, Length, Regexp
from dotenv import load_dotenv
from supabase import create_client, Client
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta, timezone
import uuid
import os
import logging
import requests
import secrets
import hashlib
import hmac
import bcrypt
import jwt
from functools import wraps
from contextlib import contextmanager
from html import escape as html_escape
from werkzeug.exceptions import HTTPException

load_dotenv()

# =====================================================
#  STARTUP CONFIGURATION + VALIDATION
# =====================================================

def env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")


def validate_config() -> None:
    required = [
        "SECRET_KEY",
        "JWT_SECRET_KEY",
        "SUPABASE_URL",
        "SUPABASE_KEY",
        "DATABASE_URL",
        "EMAIL_SERVICE_URL",
        "MAIL_USERNAME",
    ]

    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    if os.getenv("SECRET_KEY") == "fallback-dev-key":
        raise RuntimeError("SECRET_KEY must not use the old fallback development value.")

    if len(os.getenv("SECRET_KEY", "")) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters long.")

    if len(os.getenv("JWT_SECRET_KEY", "")) < 32:
        raise RuntimeError("JWT_SECRET_KEY must be at least 32 characters long.")


validate_config()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# ---- Security settings ---- #
FORCE_HTTPS = env_bool("FORCE_HTTPS", "true")
ADMIN_COOKIE_NAME = os.getenv("ADMIN_COOKIE_NAME", "admin_access_token")
ADMIN_IDLE_TIMEOUT_MINUTES = int(os.getenv("ADMIN_IDLE_TIMEOUT_MINUTES", "30"))
ADMIN_OTP_EXPIRY_MINUTES = int(os.getenv("ADMIN_OTP_EXPIRY_MINUTES", "10"))
OTP_LOCKOUT_MINUTES = int(os.getenv("OTP_LOCKOUT_MINUTES", "15"))
JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = "HS256"

app.config.update(
    SESSION_COOKIE_SECURE=FORCE_HTTPS,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    WTF_CSRF_TIME_LIMIT=1800,
)

# CORS is disabled by default. If you need it, set ALLOWED_CORS_ORIGINS as a comma-separated list.
allowed_origins = [origin.strip() for origin in os.getenv("ALLOWED_CORS_ORIGINS", "").split(",") if origin.strip()]
if allowed_origins:
    CORS(app, origins=allowed_origins, supports_credentials=True)

csrf = CSRFProtect(app)

# Local memory store for now, per your instruction. Change to Redis in production.
RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri=RATELIMIT_STORAGE_URI,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Supabase Configuration
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# SMTP / email microservice configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", 10))
SMTP_USE_STARTTLS = os.getenv("SMTP_USE_STARTTLS", "true").lower() in ("1", "true", "yes")
EMAIL_SERVICE_URL = os.environ["EMAIL_SERVICE_URL"]
ADMIN_NOTIFICATION_EMAIL = os.environ["MAIL_USERNAME"]

ADMIN_ROLES = {"support", "manager", "super_admin"}

# =====================================================
#  DATABASE HELPERS
# =====================================================

def get_db_connection():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        logger.error("Database connection failed: %s", e)
        return None


@contextmanager
def db_cursor(cursor_factory=None):
    conn = get_db_connection()
    if not conn:
        raise RuntimeError("Database connection failed")
    try:
        with conn:
            with conn.cursor(cursor_factory=cursor_factory) as cursor:
                yield cursor
    finally:
        conn.close()


# =====================================================
#  SECURITY HELPERS
# =====================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code: str) -> str:
    return hmac.new(JWT_SECRET_KEY.encode("utf-8"), code.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equals(value_a: str, value_b: str) -> bool:
    return hmac.compare_digest(value_a or "", value_b or "")


def create_admin_jwt(admin: dict) -> str:
    issued_at = now_utc()
    expires_at = issued_at + timedelta(minutes=ADMIN_IDLE_TIMEOUT_MINUTES)
    payload = {
        "sub": str(admin["id"]),
        "email": admin["email"],
        "role": admin["role"],
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "typ": "admin_access",
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_admin_jwt(token: str):
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "admin_access":
            return None
        if payload.get("role") not in ADMIN_ROLES:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def set_admin_cookie(response, admin_payload_or_row: dict):
    token = create_admin_jwt(admin_payload_or_row)
    response.set_cookie(
        ADMIN_COOKIE_NAME,
        token,
        max_age=ADMIN_IDLE_TIMEOUT_MINUTES * 60,
        secure=FORCE_HTTPS,
        httponly=True,
        samesite="Lax",
    )
    return response


def clear_admin_cookie(response):
    response.delete_cookie(
        ADMIN_COOKIE_NAME, secure=FORCE_HTTPS, httponly=True, samesite="Lax")
    return response


def wants_json_response() -> bool:
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"


def current_admin_payload():
    return decode_admin_jwt(request.cookies.get(ADMIN_COOKIE_NAME))


def admin_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            admin = current_admin_payload()
            if not admin:
                if wants_json_response():
                    return jsonify({"error": "Admin login required"}), 401
                flash("Your admin session has expired. Please log in again.")
                return redirect(url_for("admin_login", next=request.path))

            if allowed_roles and admin.get("role") not in allowed_roles:
                if wants_json_response():
                    return jsonify({"error": "Forbidden"}), 403
                abort(403)

            g.admin = admin
            result = view_func(*args, **kwargs)
            response = make_response(result)
            # Sliding expiry: refresh JWT cookie on every valid admin request.
            refreshed_payload = {
                "id": admin["sub"],
                "email": admin["email"],
                "role": admin["role"],
            }
            return set_admin_cookie(response, refreshed_payload)
        return wrapper
    return decorator


@app.before_request
def enforce_https():
    if not FORCE_HTTPS:
        return None
    if request.is_secure:
        return None
    if request.host.startswith("localhost") or request.host.startswith("127.0.0.1"):
        return None
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "http")
    if forwarded_proto == "https":
        return None
    return redirect(request.url.replace("http://", "https://", 1), code=301)


def bootstrap_admin_if_required():
    bootstrap_email = os.getenv("ADMIN_BOOTSTRAP_EMAIL", "").lower().strip()
    bootstrap_password = os.getenv("ADMIN_BOOTSTRAP_PASSWORD", "")
    bootstrap_role = os.getenv("ADMIN_BOOTSTRAP_ROLE", "super_admin")

    if bootstrap_role not in ADMIN_ROLES:
        raise RuntimeError("ADMIN_BOOTSTRAP_ROLE must be one of: support, manager, super_admin")

    with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
        cursor.execute("SELECT COUNT(*) AS count FROM admins")
        admin_count = cursor.fetchone()["count"]

        if admin_count == 0:
            if not bootstrap_email or not bootstrap_password:
                raise RuntimeError(
                    "No admin users exist. Set ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD for first startup."
                )
            if len(bootstrap_password) < 12:
                raise RuntimeError("ADMIN_BOOTSTRAP_PASSWORD must be at least 12 characters long.")

            cursor.execute(
                """
                INSERT INTO admins (email, password_hash, role, is_active)
                VALUES (%s, %s, %s, TRUE)
                """,
                (bootstrap_email, hash_password(bootstrap_password), bootstrap_role),
            )
            logger.warning("Created initial bootstrap admin account for %s. Rotate this password immediately.", bootstrap_email)


# Call after DB migration has been applied.
# If you have not run the SQL migration yet, comment this line once, run migration, then enable it again.
try:
    bootstrap_admin_if_required()
except Exception as bootstrap_error:
    logger.error("Admin bootstrap failed: %s", bootstrap_error)
    raise

# =====================================================
#  EMAIL HELPER FUNCTION
# =====================================================

def send_email_via_smtp(recipient, subject, html_body):
    """
    Sends email by calling the FastAPI email microservice.
    Returns True if successful, False otherwise.
    """
    if not recipient:
        logger.error("Email recipient is missing")
        return False

    try:
        response = requests.post(
            EMAIL_SERVICE_URL,
            json={"to": recipient, "subject": subject, "html": html_body},
            timeout=10,
        )
        response.raise_for_status()
        res_json = response.json()

        if res_json.get("success"):
            logger.info("Email sent successfully to %s via service", recipient)
            return True

        logger.error("Email service returned error: %s", res_json.get("error"))
        return False
    except Exception as e:
        logger.error("Failed to contact email service: %s", e)
        return False


# =====================================================
#  FORM CLASS
# =====================================================
class TicketForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    account = StringField(
        "Account",
        render_kw={
            "type": "text",
            "inputmode": "numeric",
            "pattern": "[0-9]*",
            "minlength": "10",
            "maxlength": "10",
            "style": "width: 100%; -moz-appearance: textfield;",
            "oninput": "this.value = this.value.replace(/[^0-9]/g, '')",
        },
        validators=[
            DataRequired(),
            Length(min=10, max=10, message="Account number must be exactly 10 digits."),
            Regexp("^[0-9]{10}$", message="Account number must contain only digits."),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    reference = StringField("Reference")
    error_type = SelectField(
        "Error Type",
        choices=[
            ("", "Select Error Type"),
            ("payment_failed", "Payment Failed"),
            ("wrong_deduction", "Wrong Deduction"),
            ("not_credited", "Not Credited"),
            ("bank_one_loading", "BankOne Issue"),
            ("other", "Other"),
        ],
        validators=[DataRequired()],
    )
    description = TextAreaField("Description", validators=[DataRequired()])
    file = FileField("Upload Screenshot (Optional)", validators=[FileAllowed(["jpg", "png", "pdf"], "Only images and PDFs are allowed.")])


# =====================================================
#  1. PUBLIC ROUTES (CREATE TICKET)
# =====================================================
@app.route("/", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def form_view():
    form = TicketForm()
    if form.validate_on_submit():
        ticket_id = f"TICKET-{str(uuid.uuid4())[:8]}"
        public_url = None
        uploaded_file = form.file.data

        # File security hardening is Phase 2. This keeps your current storage behaviour for now.
        if uploaded_file:
            try:
                filename = f"{ticket_id}_{uuid.uuid4()}"
                file_content = uploaded_file.read()
                supabase.storage.from_("uploads").upload(filename, file_content, {"content-type": uploaded_file.content_type})
                public_url = supabase.storage.from_("uploads").get_public_url(filename)
            except Exception as e:
                logger.error("Supabase upload error: %s", e)
                flash("Error uploading file. Please try again.")

        try:
            with db_cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO tickets (ticket_id, fullname, account_number, email, reference, error_type, description, file_path, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Open')
                    """,
                    (
                        ticket_id,
                        form.name.data,
                        form.account.data,
                        form.email.data.lower().strip(),
                        form.reference.data,
                        form.error_type.data,
                        form.description.data,
                        public_url,
                    ),
                )
                cursor.execute(
                    "INSERT INTO messages (ticket_id, sender_type, content) VALUES (%s, 'user', %s)",
                    (ticket_id, form.description.data),
                )

            tracking_link = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            subject = f"New Ticket: {ticket_id}"
            html_content = f"""
                <h3>New Ticket Received</h3>
                <p><strong>From:</strong> {html_escape(form.name.data)}</p>
                <p><strong>Account:</strong> {html_escape(form.account.data)}</p>
                <p><strong>Issue:</strong> {html_escape(form.error_type.data)}</p>
                <br>
                <a href="{html_escape(tracking_link)}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Ticket</a>
                <p style="margin-top:20px; font-size:12px; color:#666;">Or copy link: {html_escape(tracking_link)}</p>
            """
            ok = send_email_via_smtp(ADMIN_NOTIFICATION_EMAIL, subject, html_content)
            if not ok:
                logger.warning("Admin alert email failed to send.")

            flash(f"Ticket {ticket_id} submitted successfully.")
            return redirect("/")
        except Exception as e:
            logger.error("Ticket submission error: %s", e)
            flash("An error occurred while submitting your ticket.")

    return render_template("index.html", form=form)


# =====================================================
#  2. USER AUTHENTICATION (OTP FLOW HARDENED)
# =====================================================
@app.route("/auth/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def user_login():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()

        generic_message = "If an account exists for that email, a code has been sent."
        if not email:
            flash(generic_message)
            return render_template("login_verify.html", email=email)

        try:
            with db_cursor() as cursor:
                cursor.execute("SELECT 1 FROM tickets WHERE email = %s LIMIT 1", (email,))
                exists = cursor.fetchone()

                if exists:
                    code = generate_otp()
                    expires = now_utc() + timedelta(minutes=10)
                    cursor.execute(
                        """
                        INSERT INTO otps (email, code, code_hash, expires_at, failed_attempts, locked_until)
                        VALUES (%s, NULL, %s, %s, 0, NULL)
                        ON CONFLICT (email) DO UPDATE SET
                            code = NULL,
                            code_hash = EXCLUDED.code_hash,
                            expires_at = EXCLUDED.expires_at,
                            failed_attempts = 0,
                            locked_until = NULL;
                        """,
                        (email, hash_otp(code), expires),
                    )

                    verify_link = url_for("verify_code", email=email, _external=True)
                    subject = "Your Access Code"
                    html_content = f"""
                    <!DOCTYPE html>
                    <html>
                    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f8;">
                        <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
                            <div style="background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;">
                                <h2 style="color: #333333; margin-top: 0;">Verify Your Login</h2>
                                <p style="color: #666666; font-size: 16px;">Use the code below to access your dashboard.</p>
                                <div style="background-color: #eef2f7; padding: 20px; margin: 30px 0; border-radius: 8px; letter-spacing: 5px;">
                                    <span style="font-size: 32px; font-weight: bold; color: #2c3e50; font-family: monospace;">{html_escape(code)}</span>
                                </div>
                                <a href="{html_escape(verify_link)}" style="background-color: #28a745; color: #ffffff; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Automatically</a>
                                <p style="margin-top: 30px; font-size: 12px; color: #999999;">This code will expire in 10 minutes.<br>If you didn't request this code, you can safely ignore this email.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    if not send_email_via_smtp(email, subject, html_content):
                        logger.warning("OTP email failed to send to %s", email)
        except Exception as e:
            logger.error("Login error: %s", e)

        flash(generic_message)
        return render_template("login_verify.html", email=email)

    return render_template("login_email.html")


@app.route("/auth/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_code():
    if request.method == "GET":
        email = request.args.get("email")
        if not email:
            return redirect("/auth/login")
        return render_template("login_verify.html", email=email)

    email = request.form.get("email", "").lower().strip()
    code = request.form.get("code", "").strip()

    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM otps WHERE email = %s", (email,))
            otp = cursor.fetchone()

            if not otp:
                flash("Invalid or expired code.")
                return render_template("login_verify.html", email=email)

            if otp.get("locked_until") and otp["locked_until"] > now_utc():
                flash("Too many failed attempts. Please request a new code later.")
                return render_template("login_verify.html", email=email)

            if otp["expires_at"] <= now_utc():
                cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
                flash("Invalid or expired code.")
                return render_template("login_verify.html", email=email)

            valid = constant_time_equals(hash_otp(code), otp.get("code_hash"))
            if valid:
                session.permanent = True
                session["user_email"] = email
                cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
                return redirect("/my-tickets")

            failed_attempts = int(otp.get("failed_attempts") or 0) + 1
            locked_until = now_utc() + timedelta(minutes=OTP_LOCKOUT_MINUTES) if failed_attempts >= 5 else None
            cursor.execute(
                "UPDATE otps SET failed_attempts = %s, locked_until = %s WHERE email = %s",
                (failed_attempts, locked_until, email),
            )
    except Exception as e:
        logger.error("OTP verification error: %s", e)

    flash("Invalid or expired code.")
    return render_template("login_verify.html", email=email)


@app.route("/auth/logout")
def logout():
    session.pop("user_email", None)
    return redirect("/")


# =====================================================
#  3. USER DASHBOARD ROUTES
# =====================================================
@app.route("/my-tickets")
def my_tickets():
    if "user_email" not in session:
        return redirect("/auth/login")

    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM tickets WHERE email = %s ORDER BY created_at DESC", (session["user_email"],))
            tickets = cursor.fetchall()
        return render_template("my_tickets_list.html", tickets=tickets, user_email=session["user_email"])
    except Exception as e:
        logger.error("My tickets error: %s", e)
        return "Database Error", 500


@app.route("/track/<ticket_id>")
def track_ticket(ticket_id):
    if "user_email" not in session:
        return redirect("/auth/login")

    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
            ticket = cursor.fetchone()
            if not ticket or ticket["email"] != session["user_email"]:
                abort(404)
            cursor.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
            messages = cursor.fetchall()
        return render_template("track_ticket.html", ticket=ticket, messages=messages)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Track ticket error: %s", e)
        return "Database Error", 500


# =====================================================
#  4. ADMIN AUTH + ADMIN ROUTES
# =====================================================
@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    if current_admin_payload():
        return redirect(url_for("view_tickets"))

    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "")

        generic_error = "Invalid admin login details."
        try:
            with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM admins WHERE email = %s AND is_active = TRUE", (email,))
                admin = cursor.fetchone()

                if not admin or not verify_password(password, admin["password_hash"]):
                    flash(generic_error)
                    return render_template("admin_login.html", stage="password", email=email)

                code = generate_otp()
                expires = now_utc() + timedelta(minutes=ADMIN_OTP_EXPIRY_MINUTES)
                cursor.execute(
                    """
                    INSERT INTO admin_otps (admin_id, code_hash, expires_at, failed_attempts, locked_until)
                    VALUES (%s, %s, %s, 0, NULL)
                    ON CONFLICT (admin_id) DO UPDATE SET
                        code_hash = EXCLUDED.code_hash,
                        expires_at = EXCLUDED.expires_at,
                        failed_attempts = 0,
                        locked_until = NULL;
                    """,
                    (admin["id"], hash_otp(code), expires),
                )

            verify_link = url_for("admin_verify_otp", _external=True)
            subject = "Your Admin Login Code"
            html_content = f"""
                <h3>Admin Login Verification</h3>
                <p>Your admin login code is:</p>
                <p style="font-size:28px; letter-spacing:4px;"><strong>{html_escape(code)}</strong></p>
                <p>This code expires in {ADMIN_OTP_EXPIRY_MINUTES} minutes.</p>
                <p><a href="{html_escape(verify_link)}">Continue login</a></p>
            """
            if not send_email_via_smtp(email, subject, html_content):
                flash("Could not send admin OTP. Please try again.")
                return render_template("admin_login.html", stage="password", email=email)

            session.permanent = True
            session["pending_admin_email"] = email
            flash("Enter the OTP sent to your admin email.")
            return redirect(url_for("admin_verify_otp"))
        except Exception as e:
            logger.error("Admin login error: %s", e)
            flash(generic_error)

    return render_template("admin_login.html", stage="password")


@app.route("/admin/verify-otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def admin_verify_otp():
    pending_email = session.get("pending_admin_email")
    if not pending_email:
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        try:
            with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM admins WHERE email = %s AND is_active = TRUE", (pending_email,))
                admin = cursor.fetchone()
                if not admin:
                    session.pop("pending_admin_email", None)
                    flash("Invalid admin login details.")
                    return redirect(url_for("admin_login"))

                cursor.execute("SELECT * FROM admin_otps WHERE admin_id = %s", (admin["id"],))
                otp = cursor.fetchone()
                if not otp:
                    flash("Invalid or expired admin OTP.")
                    return render_template("admin_login.html", stage="otp", email=pending_email)

                if otp.get("locked_until") and otp["locked_until"] > now_utc():
                    flash("Too many failed admin OTP attempts. Please try again later.")
                    return render_template("admin_login.html", stage="otp", email=pending_email)

                if otp["expires_at"] <= now_utc():
                    cursor.execute("DELETE FROM admin_otps WHERE admin_id = %s", (admin["id"],))
                    flash("Invalid or expired admin OTP.")
                    return render_template("admin_login.html", stage="otp", email=pending_email)

                if constant_time_equals(hash_otp(code), otp["code_hash"]):
                    cursor.execute("DELETE FROM admin_otps WHERE admin_id = %s", (admin["id"],))
                    cursor.execute("UPDATE admins SET last_login_at = NOW() WHERE id = %s", (admin["id"],))
                    session.pop("pending_admin_email", None)

                    response = make_response(redirect(url_for("view_tickets")))
                    return set_admin_cookie(response, admin)

                failed_attempts = int(otp.get("failed_attempts") or 0) + 1
                locked_until = now_utc() + timedelta(minutes=OTP_LOCKOUT_MINUTES) if failed_attempts >= 5 else None
                cursor.execute(
                    "UPDATE admin_otps SET failed_attempts = %s, locked_until = %s WHERE admin_id = %s",
                    (failed_attempts, locked_until, admin["id"]),
                )
        except Exception as e:
            logger.error("Admin OTP verification error: %s", e)

        flash("Invalid or expired admin OTP.")

    return render_template("admin_login.html", stage="otp", email=pending_email)


@app.route("/admin/logout")
def admin_logout():
    session.pop("pending_admin_email", None)
    response = make_response(redirect(url_for("admin_login")))
    return clear_admin_cookie(response)


@app.route("/tickets", methods=["GET"])
@admin_required("support", "manager", "super_admin")
def view_tickets():
    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM tickets ORDER BY CASE WHEN status='Open' THEN 0 ELSE 1 END, created_at DESC")
            tickets = cursor.fetchall()
        return render_template("tickets.html", tickets=tickets, admin=g.admin)
    except Exception as e:
        logger.error("Admin tickets error: %s", e)
        return "Database Error", 500


@app.route("/ticket/<ticket_id>")
@admin_required("support", "manager", "super_admin")
def ticket_detail(ticket_id):
    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
            ticket = cursor.fetchone()
            if not ticket:
                abort(404)

            cursor.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
            messages = cursor.fetchall()
        return render_template("ticket_detail.html", ticket=ticket, messages=messages, admin=g.admin)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Admin ticket detail error: %s", e)
        return "Database Error", 500


@app.route("/close_ticket/<ticket_id>", methods=["POST"])
@admin_required("manager", "super_admin")
def close_ticket(ticket_id):
    try:
        with db_cursor() as cursor:
            cursor.execute("UPDATE tickets SET status = 'Closed', closed_at = NOW() WHERE ticket_id = %s", (ticket_id,))
            if cursor.rowcount == 0:
                abort(404)
        return redirect("/tickets")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Close ticket error: %s", e)
        return "Database Error", 500


@app.route("/delete_ticket/<ticket_id>", methods=["POST"])
@admin_required("super_admin")
def delete_ticket(ticket_id):
    try:
        with db_cursor() as cursor:
            cursor.execute("DELETE FROM tickets WHERE ticket_id = %s", (ticket_id,))
            if cursor.rowcount == 0:
                abort(404)
        return redirect("/tickets")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Delete ticket error: %s", e)
        return "Database Error", 500


# =====================================================
#  5. API (CHAT) WITH OWNERSHIP CHECKS
# =====================================================
@app.route("/api/reply", methods=["POST"])
@limiter.limit("30 per minute")
def api_reply():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["ticket_id", "sender_type", "message"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Missing field: {field}"}), 400

    ticket_id = data.get("ticket_id")
    sender_type = data.get("sender_type")
    message_content = data.get("message")

    if sender_type not in ("admin", "user"):
        return jsonify({"error": "Invalid sender_type"}), 400

    admin_payload = current_admin_payload()
    user_email = session.get("user_email")

    if sender_type == "admin" and not admin_payload:
        return jsonify({"error": "Unauthorized"}), 403
    if sender_type == "user" and not user_email:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT email FROM tickets WHERE ticket_id = %s", (ticket_id,))
            ticket = cursor.fetchone()
            if not ticket:
                return jsonify({"error": "Ticket not found"}), 404

            # Fix #16: user must own the ticket before any message write.
            if sender_type == "user" and ticket["email"] != user_email:
                return jsonify({"error": "Unauthorized"}), 403

            cursor.execute(
                "INSERT INTO messages (ticket_id, sender_type, content) VALUES (%s, %s, %s)",
                (ticket_id, sender_type, message_content),
            )

            user_email_for_notice = ticket["email"]

        if sender_type == "admin":
            tracking_link = url_for("track_ticket", ticket_id=ticket_id, _external=True)
            subject = f"Update on Ticket {ticket_id}"
            html_content = f"""
                <!DOCTYPE html>
                <html>
                <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f8;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
                        <div style="background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                            <h2 style="color: #333333; margin-top: 0; font-size: 24px;">New Reply Received</h2>
                            <p style="color: #666666; font-size: 16px; line-height: 1.5;">There is a new update regarding your ticket <strong>#{html_escape(ticket_id)}</strong>.</p>
                            <div style="background-color: #f8f9fa; border-left: 5px solid #007bff; padding: 15px 20px; margin: 25px 0; border-radius: 4px;">
                                <p style="margin: 0; color: #555555; font-style: italic; font-size: 16px;">&quot;{html_escape(message_content)}&quot;</p>
                            </div>
                            <div style="text-align: center; margin-top: 30px;">
                                <a href="{html_escape(tracking_link)}" style="background-color: #007bff; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">View Full Conversation</a>
                            </div>
                            <p style="margin-top: 30px; font-size: 12px; color: #999999; text-align: center;">If you did not submit this ticket, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            """
            if not send_email_via_smtp(user_email_for_notice, subject, html_content):
                logger.warning("Failed to send reply notification to %s", user_email_for_notice)

        response = jsonify({"status": "success"})
        if admin_payload:
            response = set_admin_cookie(response, {"id": admin_payload["sub"], "email": admin_payload["email"], "role": admin_payload["role"]})
        return response
    except Exception as e:
        logger.error("API Error: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/ticket/<ticket_id>/messages", methods=["GET"])
@limiter.limit("60 per minute")
def get_ticket_messages(ticket_id):
    admin_payload = current_admin_payload()
    user_email = session.get("user_email")

    try:
        with db_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT email FROM tickets WHERE ticket_id = %s", (ticket_id,))
            ticket = cursor.fetchone()
            if not ticket:
                return jsonify({"error": "Ticket not found"}), 404

            if not admin_payload and (not user_email or ticket["email"] != user_email):
                return jsonify({"error": "Unauthorized"}), 403

            cursor.execute(
                "SELECT sender_type, content, created_at FROM messages WHERE ticket_id = %s ORDER BY created_at ASC",
                (ticket_id,),
            )
            messages = cursor.fetchall()

        response = jsonify(messages)
        if admin_payload:
            response = set_admin_cookie(response, {"id": admin_payload["sub"], "email": admin_payload["email"], "role": admin_payload["role"]})
        return response
    except Exception as e:
        logger.error("Error fetching messages: %s", e)
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
