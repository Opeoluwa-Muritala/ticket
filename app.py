from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_cors import CORS # Add CORS
from wtforms import StringField, TextAreaField, SelectField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Email, Length, Regexp
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from supabase import create_client, Client
import psycopg2
import psycopg2.extras
import uuid
import os

load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-dev-key')

# ---- Configuration ---- #

# Mail Configuration
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') # Move specific credentials to .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") # Use the SERVICE_ROLE key for backend uploads
DATABASE_URL = os.getenv("DATABASE_URL") # PostgreSQL Connection URI

# Initialize Supabase Client (For Storage)
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# ---- Form Class  ---- #
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
    conn = psycopg2.connect(DATABASE_URL)
    return conn

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
                supabase.storage.from_("uploads").upload(filename, file_content, {"content-type": uploaded_file.content_type})
                public_url = supabase.storage.from_("uploads").get_public_url(filename)
            except Exception as e:
                flash(f"Upload Error: {str(e)}")

        # 2. Insert into DB
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tickets (ticket_id, fullname, account_number, email, reference, error_type, description, file_path, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Open')
            """, (ticket_id, form.name.data, int(form.account.data), form.email.data, form.reference.data, form.error_type.data, form.description.data, public_url))
           
            # Add initial message
            cursor.execute("INSERT INTO messages (ticket_id, sender_type, content) VALUES (%s, 'user', %s)", (ticket_id, form.description.data))
           
            conn.commit()
            cursor.close()
            conn.close()
           
            # Send Email Alert to Admin
            try:
                msg = Message(f"New Ticket: {ticket_id}", sender=app.config['MAIL_USERNAME'], recipients=[app.config['MAIL_USERNAME']])
                msg.body = f"New ticket from {form.name.data}.\nLink: {url_for('view_tickets', _external=True)}"
                mail.send(msg)
            except: pass

            flash(f"Ticket {ticket_id} submitted successfully.")
            return redirect('/')
        except Exception as e:
            flash(f"Database error: {str(e)}")

    return render_template('index.html', form=form)

# =====================================================
#  2. USER AUTHENTICATION (OTP Flow)
# =====================================================
@app.route('/auth/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email').lower().strip()
        conn = get_db_connection()
        cursor = conn.cursor()
       
        # Check if email exists
        cursor.execute("SELECT 1 FROM tickets WHERE email = %s LIMIT 1", (email,))
        if not cursor.fetchone():
            conn.close()
            # Security: Don't reveal email doesn't exist, just show verify screen
            return render_template('login_verify.html', email=email)

        # Generate & Store OTP
        # code = str(random.randint(100000, 999999))
        code =123456
        # expires = datetime.now() + timedelta(minutes=10)
        # cursor.execute("""
        #     INSERT INTO otps (email, code, expires_at) VALUES (%s, %s, %s)
        #     ON CONFLICT (email) DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at;
        # """, (email, code, expires))
        # conn.commit()
        # conn.close()

        # Email Code
        try:
            msg = Message("Your Access Code", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Your code is: {code}"
            mail.send(msg)
        except: pass

        return render_template('login_verify.html', email=email)
    return render_template('login_email.html')

@app.route('/auth/verify', methods=['POST'])
def verify_code():
    email = request.form.get('email')
    code = request.form.get('code')
    conn = get_db_connection()
    cursor = conn.cursor()
    # cursor.execute("SELECT * FROM otps WHERE email = %s AND code = %s AND expires_at > NOW()", (email, code))
   
    # if cursor.fetchone():
    #     session['user_email'] = email
    #     cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
    #     conn.commit()
    #     conn.close()
    #     return redirect('/my-tickets')
   
    # conn.close()
    if (code == "123456"):
        session['user_email'] = email
        return redirect('/my-tickets')
    
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
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM tickets WHERE email = %s ORDER BY created_at DESC", (session['user_email'],))
    tickets = cursor.fetchall()
    conn.close()
    return render_template('my_tickets_list.html', tickets=tickets, user_email=session['user_email'])

@app.route('/track/<ticket_id>')
def track_ticket(ticket_id):
    # Optional: Add security check here to ensure ticket belongs to session['user_email']
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
    ticket = cursor.fetchone()
   
    if ticket:
        cursor.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
        messages = cursor.fetchall()
        conn.close()
        return render_template('track_ticket.html', ticket=ticket, messages=messages)
   
    conn.close()
    return redirect('/')

# =====================================================
#  4. ADMIN ROUTES
# =====================================================
@app.route('/tickets', methods=['GET', 'POST'])
def view_tickets():
    if session.get('admin_authenticated'):
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM tickets ORDER BY CASE WHEN status='Open' THEN 0 ELSE 1 END, created_at DESC")
        tickets = cursor.fetchall()
        conn.close()
        return render_template('tickets.html', tickets=tickets)
   
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
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
    ticket = cursor.fetchone()
    if ticket:
        cursor.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY created_at ASC", (ticket_id,))
        messages = cursor.fetchall()
        conn.close()
        return render_template('ticket_detail.html', ticket=ticket, messages=messages)
    return redirect('/tickets')

@app.route('/close_ticket/<ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE tickets SET status = 'Closed', closed_at = NOW() WHERE ticket_id = %s", (ticket_id,))
    conn.commit()
    conn.close()
    return redirect('/tickets')

@app.route('/delete_ticket/<ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tickets WHERE ticket_id = %s", (ticket_id,))
    conn.commit()
    conn.close()
    return redirect('/tickets')

# =====================================================
#  5. API (Chat)
# =====================================================
@app.route('/api/reply', methods=['POST'])
def api_reply():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (ticket_id, sender_type, content) VALUES (%s, %s, %s)",
                       (data['ticket_id'], data['sender_type'], data['message']))
        conn.commit()
       
        # If Admin replied, email User
        if data['sender_type'] == 'admin':
            cursor.execute("SELECT email FROM tickets WHERE ticket_id = %s", (data['ticket_id'],))
            user_email = cursor.fetchone()[0]
            msg = Message(f"Update on Ticket {data['ticket_id']}", sender=app.config['MAIL_USERNAME'], recipients=[user_email])
            msg.body = f"New reply: \n\n{data['message']}"
            mail.send(msg)
           
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)