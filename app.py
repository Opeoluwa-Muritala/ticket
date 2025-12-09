from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify, abort
from flask_mail import Mail, Message  # Using Flask-Mail for Gmail
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, TextAreaField, SelectField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Email, Length, Regexp
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from supabase import create_client, Client
import psycopg2
import psycopg2.extras
import random
from datetime import datetime, timedelta
import uuid
import os
import logging

load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-dev-key')

# ---- Configuration ---- #

# Security & Rate Limiting
csrf = CSRFProtect(app) 
limiter = Limiter(key_func=get_remote_address, app=app) 

# Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---- GMAIL SMTP CONFIGURATION ---- #
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
# Your real Gmail address
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
# Your Google App Password (16 chars) from .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# ---- Form Class ---- #
class TicketForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    account = StringField('Account', 
        render_kw={
            "type": "text",
            "inputmode": "numeric",
            "pattern": "[0-9]*",
            "minlength": "10",
            "maxlength": "10",
            "style": "width: 100%; -moz-appearance: textfield;",
            "oninput": "this.value = this.value.replace(/[^0-9]/g, '')"
        },
        validators=[
            DataRequired(),
            Length(min=10, max=10, message="Account number must be exactly 10 digits."),
            Regexp('^[0-9]{10}$', message="Account number must contain only digits.")
        ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    reference = StringField('Reference')
    error_type = SelectField('Error Type', choices=[
        ('', 'Select Error Type'),
        ('payment_failed', 'Payment Failed'),
        ('wrong_deduction', 'Wrong Deduction'),
        ('not_credited', 'Not Credited'),
        ('bank_one_loading', 'BankOne Issue'),
        ('other', 'Other'),
    ], validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    file = FileField('Upload Screenshot (Optional)', validators=[
        FileAllowed(['jpg', 'png', 'pdf'], 'Only images and PDFs are allowed.')
    ])

# ---- Database Helper ---- #
def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return None

# =====================================================
#  1. PUBLIC ROUTES (Create Ticket)
# =====================================================
@app.route('/', methods=['GET', 'POST'])
def form_view():
    form = TicketForm()
    if form.validate_on_submit():
        ticket_id = f"TICKET-{str(uuid.uuid4())[:8]}"
        public_url = None
        uploaded_file = form.file.data

        # 1. Upload to Supabase
        if uploaded_file:
            try:
                filename = f"{ticket_id}_{secure_filename(uploaded_file.filename)}"
                file_content = uploaded_file.read()
                # Bucket name is "uploads"
                res = supabase.storage.from_("uploads").upload(filename, file_content, {"content-type": uploaded_file.content_type})
                public_url = supabase.storage.from_("uploads").get_public_url(filename)
            except Exception as e:
                logger.error(f"Supabase upload error: {e}")
                flash("Error uploading file. Please try again.")

        # 2. Insert into DB
        conn = get_db_connection()
        if not conn:
            flash("System error. Please try again later.")
            return render_template('index.html', form=form)

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tickets (ticket_id, fullname, account_number, email, reference, error_type, description, file_path, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Open')
            """, (ticket_id, form.name.data, int(form.account.data), form.email.data.lower(), form.reference.data, form.error_type.data, form.description.data, public_url))
            
            # Add initial message
            cursor.execute("INSERT INTO messages (ticket_id, sender_type, content) VALUES (%s, 'user', %s)", (ticket_id, form.description.data))
            
            conn.commit()
            
            # 3. Send Email Alert to Admin (Gmail)
            tracking_link = url_for('ticket_detail', ticket_id=ticket_id, _external=True)
            try:
                msg = Message(f"New Ticket: {ticket_id}", recipients=[app.config['MAIL_USERNAME']])
                msg.html = f"""
                    <h3>New Ticket Received</h3>
                    <p><strong>From:</strong> {form.name.data}</p>
                    <p><strong>Account:</strong> {form.account.data}</p>
                    <p><strong>Issue:</strong> {form.error_type.data}</p>
                    <br>
                    <a href="{tracking_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Ticket</a>
                    <p style="margin-top:20px; font-size:12px; color:#666;">Or copy link: {tracking_link}</p>
                """
                mail.send(msg)
            except Exception as e:
                logger.warning(f"Email failed to send: {e}")

            flash(f"Ticket {ticket_id} submitted successfully.")
            return redirect('/')
        except Exception as e:
            conn.rollback()
            logger.error(f"Database insertion error: {e}")
            flash("An error occurred while submitting your ticket.")
        finally:
            cursor.close()
            conn.close()

    return render_template('index.html', form=form)

# =====================================================
#  2. USER AUTHENTICATION (OTP Flow)
# =====================================================
@app.route('/auth/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def user_login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        
        if not email:
            flash("Please enter a valid email.")
            return render_template('login_email.html')

        conn = get_db_connection()
        if not conn:
            flash("Service unavailable.")
            return render_template('login_email.html')

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM tickets WHERE email = %s LIMIT 1", (email,))
            exists = cursor.fetchone()
            
            if not exists:
                # Security: Don't reveal email doesn't exist
                return render_template('login_verify.html', email=email)

            # Generate & Store OTP
            code = str(random.randint(100000, 999999))
            expires = datetime.now() + timedelta(minutes=10)
            cursor.execute("""
                INSERT INTO otps (email, code, expires_at) VALUES (%s, %s, %s)
                ON CONFLICT (email) DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at;
            """, (email, code, expires))
            conn.commit()
            conn.close()
            
            # Email Code (Gmail)
            verify_link = url_for('verify_code', email=email, _external=True)
            try:
                msg = Message("Your Access Code", recipients=[email])
                msg.html = f"""
                    <h3>Your Access Code: {code}</h3>
                    <p>Please enter this code to access your dashboard.</p>
                    <br>
                    <a href="{verify_link}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Enter Code Now</a>
                    <p style="margin-top:20px; color:#666;">This code expires in 10 minutes.</p>
                """
                mail.send(msg)
            except Exception as e:
                 logger.error(f"OTP Email failed: {e}")
                 # Proceeding without flash to avoid leaking user existence
                 
        except Exception as e:
            logger.error(f"Login error: {e}")
        finally:
             if conn: conn.close()

        return render_template('login_verify.html', email=email)
    return render_template('login_email.html')

@app.route('/auth/verify', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_code():
    # HANDLE GET (Link from Email)
    if request.method == 'GET':
        email = request.args.get('email')
        if not email:
            return redirect('/auth/login')
        return render_template('login_verify.html', email=email)

    # HANDLE POST (Form Submission)
    email = request.form.get('email')
    code = request.form.get('code')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM otps WHERE email = %s AND code = %s AND expires_at > NOW()", (email, code))
   
    if cursor.fetchone():
        session['user_email'] = email
        cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
        conn.commit()
        conn.close()
        return redirect('/my-tickets')
   
    conn.close()
    flash("Invalid or expired code.")
    return render_template('login_verify.html', email=email)

@app.route('/auth/logout')
def logout():
    session.pop('user_email', None)
    return redirect('/')

# =====================================================
#  3. USER DASHBOARD ROUTES
# =====================================================
@app.route('/my-tickets')
def my_tickets():
    if 'user_email' not in session: return redirect('/auth/login')
    
    conn = get_db_connection()
    if not conn: return "Database Error", 500

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM tickets WHERE email = %s ORDER BY created_at DESC", (session['user_email'],))
        tickets = cursor.fetchall()
        return render_template('my_tickets_list.html', tickets=tickets, user_email=session['user_email'])
    finally:
        conn.close()

@app.route('/track/<ticket_id>')
def track_ticket(ticket_id):
    if 'user_email' not in session:
        return redirect('/auth/login')

    conn = get_db_connection()
    if not conn: return "Database Error", 500

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        
        if not ticket or ticket['email'] != session['user_email']:
             conn.close()
             abort(404) 
        
        cursor.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
        messages = cursor.fetchall()
        return render_template('track_ticket.html', ticket=ticket, messages=messages)
    finally:
        conn.close()

# =====================================================
#  4. ADMIN ROUTES
# =====================================================
@app.route('/tickets', methods=['GET', 'POST'])
def view_tickets():
    if session.get('admin_authenticated'):
        conn = get_db_connection()
        if not conn: return "Database Error", 500
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM tickets ORDER BY CASE WHEN status='Open' THEN 0 ELSE 1 END, created_at DESC")
            tickets = cursor.fetchall()
            return render_template('tickets.html', tickets=tickets)
        finally:
            conn.close()
    
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect('/tickets')
        flash("Incorrect password.")
    return render_template('admin_login.html')

@app.route('/ticket/<ticket_id>')
def ticket_detail(ticket_id):
    if not session.get('admin_authenticated'): return redirect('/tickets')
    
    conn = get_db_connection()
    if not conn: return "Database Error", 500
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if ticket:
            cursor.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
            messages = cursor.fetchall()
            return render_template('ticket_detail.html', ticket=ticket, messages=messages)
    finally:
        conn.close()
    return redirect('/tickets')

@app.route('/close_ticket/<ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    if not session.get('admin_authenticated'): return redirect('/tickets')

    conn = get_db_connection()
    if not conn: return "Database Error", 500
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET status = 'Closed', closed_at = NOW() WHERE ticket_id = %s", (ticket_id,))
        conn.commit()
    finally:
        conn.close()
    return redirect('/tickets')

@app.route('/delete_ticket/<ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):
    if not session.get('admin_authenticated'): return redirect('/tickets')

    conn = get_db_connection()
    if not conn: return "Database Error", 500
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tickets WHERE ticket_id = %s", (ticket_id,))
        conn.commit()
    finally:
        conn.close()
    return redirect('/tickets')

# =====================================================
#  5. API (Chat)
# =====================================================
@app.route('/api/reply', methods=['POST'])
def api_reply():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400
        
    required_fields = ['ticket_id', 'sender_type', 'message']
    for field in required_fields:
        if field not in data or not data[field]:
             return jsonify({"error": f"Missing field: {field}"}), 400

    ticket_id = data.get('ticket_id')
    sender_type = data.get('sender_type')
    message_content = data.get('message')

    if sender_type == 'admin':
         if not session.get('admin_authenticated'):
             return jsonify({"error": "Unauthorized"}), 403
    else:
        if 'user_email' not in session:
             return jsonify({"error": "Unauthorized"}), 403

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (ticket_id, sender_type, content) VALUES (%s, %s, %s)",
                       (ticket_id, sender_type, message_content))
        conn.commit()
        
        # If Admin replied, email User (Gmail)
        if sender_type == 'admin':
            cursor.execute("SELECT email FROM tickets WHERE ticket_id = %s", (ticket_id,))
            result = cursor.fetchone()
            if result:
                user_email = result[0]
                tracking_link = url_for('track_ticket', ticket_id=ticket_id, _external=True)
                
                try:
                    msg = Message(f"Update on Ticket {ticket_id}", recipients=[user_email])
                    msg.html = f"""
                        <h3>New Reply</h3>
                        <p>You have a new reply regarding your ticket.</p>
                        <blockquote style="border-left: 4px solid #ccc; padding-left: 10px; color: #555;">
                            {message_content}
                        </blockquote>
                        <br>
                        <a href="{tracking_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Full Conversation</a>
                    """
                    mail.send(msg)
                except Exception as e:
                    logger.warning(f"Failed to send email notification: {e}")
            
        return jsonify({"status": "success"})
    except Exception as e:
        conn.rollback()
        logger.error(f"API Error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()

@app.route('/api/ticket/<ticket_id>/messages', methods=['GET'])
def get_ticket_messages(ticket_id):
    is_admin = session.get('admin_authenticated')
    user_email = session.get('user_email')
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database error"}), 500
    
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT email FROM tickets WHERE ticket_id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
            
        if not is_admin and (not user_email or ticket['email'] != user_email):
             return jsonify({"error": "Unauthorized"}), 403

        cursor.execute("SELECT sender_type, content, created_at FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
        messages = cursor.fetchall()
        
        return jsonify(messages)
    except Exception as e:
        logger.error(f"Error fetching messages: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)