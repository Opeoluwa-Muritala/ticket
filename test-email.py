import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- CONFIGURATION (FILL THESE IN CAREFULLY) ---
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'muritalaopeoluwa10@gmail.com'
# IMPORTANT: This must be the 16-character App Password, NOT your login password.
# Example format: "abcd efgh ijkl mnop" (spaces don't matter)
SENDER_PASSWORD = 'hiwdsansoexbkdyy' 
RECEIVER_EMAIL = 'muritalaopeoluwa10@gmail.com' # Send to yourself

def test_send():
    try:
        print(f"Connecting to {SMTP_SERVER} on port {SMTP_PORT}...")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo() # Identify ourselves
        
        print("Starting TLS encryption...")
        server.starttls() # Secure the connection
        server.ehlo() # Re-identify as encrypted
        
        print("Logging in...")
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        print("Login Successful!")

        # Create message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = "Test Email from Python"
        body = "If you are reading this, your email configuration is working!"
        msg.attach(MIMEText(body, 'plain'))

        print("Sending email...")
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print("Email sent successfully!")
        
    except Exception as e:
        print("\n❌ FAILED TO SEND EMAIL")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {e}")
        
    finally:
        try:
            server.quit()
        except:
            pass

if __name__ == '__main__':
    test_send()