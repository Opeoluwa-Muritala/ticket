from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
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

# ---- Form Class (Unchanged) ---- #
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

# ---- Routes ---- #
@app.route('/', methods=['GET', 'POST'])
def form_view():
    form = TicketForm()
    if form.validate_on_submit():
        ticket_id = f"TICKET-{str(uuid.uuid4())[:8]}"
        public_url = None
        uploaded_file = form.file.data

        # 1. Handle File Upload to Supabase Storage
        if uploaded_file and hasattr(uploaded_file, 'filename') and uploaded_file.filename:
            try:
                secured_name = secure_filename(uploaded_file.filename)
                filename = f"{ticket_id}_{secured_name}"
                file_content = uploaded_file.read()
                
                # Upload to Supabase Bucket named 'uploads'
                res = supabase.storage.from_("uploads").upload(
                    path=filename,
                    file=file_content,
                    file_options={"content-type": uploaded_file.content_type}
                )
                # Get Public URL
                public_url = supabase.storage.from_("uploads").get_public_url(filename)
                print("File uploaded:", public_url)
            except Exception as e:
                flash(f"File upload error: {str(e)}")
                return render_template('index.html', form=form)

        # 2. Insert into PostgreSQL
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            sql = """
                INSERT INTO tickets (ticket_id, fullname, account_number, email, reference, error_type, description, file_path, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                ticket_id,
                form.name.data,
                int(form.account.data),
                form.email.data,
                form.reference.data,
                form.error_type.data,
                form.description.data,
                public_url, # Storing the full URL
                "Open"
            ))
            conn.commit()
            cursor.close()
            conn.close()
            flash(f"Ticket {ticket_id} submitted successfully.")

            # Notification email
            try:
                msg = Message(
                    subject=f"New Ticket Submitted: {ticket_id}",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[app.config['MAIL_USERNAME']]
                )
                msg.body = (f"Hello Admin,\n\nNew ticket {ticket_id} from {form.name.data}.\n"
                            f"View details: {url_for('view_tickets', _external=True)}")
                mail.send(msg)
            except Exception as e:
                print(f"Email failed: {e}") # Don't crash app if email fails

            return redirect('/')
        except Exception as e:
            flash(f"Database error: {str(e)}")
            return render_template('index.html', form=form)

    return render_template('index.html', form=form)

@app.route('/tickets', methods=['GET', 'POST'])
def view_tickets():
    if session.get('admin_authenticated'):
        try:
            conn = get_db_connection()
            # RealDictCursor allows accessing columns by name
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM tickets ORDER BY CASE WHEN status='Open' THEN 0 ELSE 1 END, created_at DESC")
            tickets = cursor.fetchall()
            cursor.close()
            conn.close()
        except Exception as e:
            flash(f"Database error: {str(e)}")
            tickets = []
        return render_template('tickets.html', tickets=tickets)
    
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect('/tickets')
        else:
            flash("Incorrect admin password.")
            return redirect('/tickets')
    return render_template('admin_login.html')

@app.route('/close_ticket/<ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Check ticket exists
        cursor.execute("SELECT email, fullname FROM tickets WHERE ticket_id = %s", (ticket_id,))
        ticket_info = cursor.fetchone()
        
        if not ticket_info:
            flash("Ticket not found.")
        else:
            # Update Ticket
            update_sql = "UPDATE tickets SET status = 'Closed', closed_at = NOW() WHERE ticket_id = %s AND status = 'Open'"
            cursor.execute(update_sql, (ticket_id,))
            conn.commit()
            
            # Send Email
            msg = Message(subject="Ticket Closed",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[ticket_info['email']])
            msg.body = f"Hello {ticket_info['fullname']}, your ticket {ticket_id} has been closed."
            mail.send(msg)
            flash(f"Ticket {ticket_id} closed.")

        cursor.close()
        conn.close()
    except Exception as e:
        flash(f"Database error: {str(e)}")
    return redirect('/tickets')

@app.route('/delete_ticket/<ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):
    if not session.get('admin_authenticated'):
        return redirect('/tickets')
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tickets WHERE ticket_id = %s", (ticket_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash(f"Ticket {ticket_id} deleted.")
    except Exception as e:
        flash(f"Database error: {str(e)}")
    return redirect('/tickets')

@app.route('/ticket/<ticket_id>')
def ticket_detail(ticket_id):
    if not session.get('admin_authenticated'):
        return redirect('/tickets')
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        cursor.close()
        conn.close()
        if ticket:
            return render_template('ticket_detail.html', ticket=ticket)
        else:
            flash("Ticket not found.")
            return redirect('/tickets')
    except Exception as e:
        flash(f"Database error: {str(e)}")
        return redirect('/tickets')

# Helper to fix common favicon 404s
@app.route('/favicon.ico')
def favicon():
    return ("", 204)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)