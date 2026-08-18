import os
import resend
from datetime import datetime
import threading

# Fallback to the environment variable or use the hardcoded one we verified
RESEND_API_KEY = os.getenv('RESEND_API_KEY', 're_KB1gXW59_GKPa3ivLTAYgpafiY5HKPrCH')
resend.api_key = RESEND_API_KEY

SENDER_EMAIL = "onboarding@resend.dev"
SUPPORT_EMAIL = "support@larshield.com"
LOGO_URL = "https://i.ibb.co/3sXZbYm/larshieldlogowhite.png" # Temporary placeholder for LarShield logo
DASHBOARD_URL = "https://wss.larshield.com/dashboard" # Update with actual frontend URL

# Base path for templates depending on where the script runs from
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'templates', 'emails')

def render_template(template_name, context):
    """Reads the HTML file and replaces {{ keys }} with context values."""
    filepath = os.path.join(TEMPLATES_DIR, template_name)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Inject standard variables
        context["{{ year }}"] = str(datetime.now().year)
        context["{{ logo_url }}"] = LOGO_URL
        context["{{ support_email }}"] = SUPPORT_EMAIL
        
        for key, value in context.items():
            content = content.replace(key, str(value))
        return content
    except Exception as e:
        print(f"[EmailService] Failed to render template {template_name}: {e}")
        return ""

def _send_email_async(to_email, subject, html_content):
    """Sends the email in a background thread to avoid blocking the main request."""
    def send():
        import psycopg2
        import uuid
        
        db_url = os.environ.get('DATABASE_URL')
        log_id = str(uuid.uuid4())
        status = 'sent'
        error_msg = None
        
        try:
            # FORCE ALL EMAILS TO THE TESTER EMAIL FOR RESEND FREE TIER LIMITATIONS
            actual_to_email = "dhruvpatel14016@gmail.com"
            r = resend.Emails.send({
                "from": SENDER_EMAIL,
                "to": actual_to_email,
                "subject": subject,
                "html": html_content
            })
            print(f"[EmailService] Email sent to {actual_to_email}. ID: {r['id']}")
        except Exception as e:
            status = 'failed'
            error_msg = str(e)
            print(f"[EmailService] Failed to send email to {to_email}: {e}")
        finally:
            if db_url:
                try:
                    conn = psycopg2.connect(db_url)
                    cur = conn.cursor()
                    cur.execute(
                        "INSERT INTO email_logs (id, recipient, subject, status, error_message, sent_at) VALUES (%s, %s, %s, %s, %s, %s)",
                        (log_id, to_email, subject, status, error_msg, datetime.utcnow())
                    )
                    conn.commit()
                    cur.close()
                    conn.close()
                except Exception as db_err:
                    print(f"[EmailService] Failed to log email to database: {db_err}")
            
    thread = threading.Thread(target=send)
    thread.start()

def send_welcome_email(user_email, user_name):
    context = {
        "{{ user_name }}": user_name,
        "{{ dashboard_link }}": DASHBOARD_URL
    }
    html = render_template('welcome.html', context)
    if html:
        _send_email_async(user_email, "Welcome to LarShield!", html)

def send_scan_started(user_email, user_name, target_url, scan_type, estimated_time="~15 minutes"):
    context = {
        "{{ user_name }}": user_name,
        "{{ target_url }}": target_url,
        "{{ scan_type }}": scan_type,
        "{{ estimated_time }}": estimated_time,
        "{{ dashboard_link }}": DASHBOARD_URL
    }
    html = render_template('scan_started.html', context)
    if html:
        _send_email_async(user_email, "Scan Initiated Successfully", html)

def send_scan_completed(user_email, user_name, target_url, duration, vulns_count, report_link, crit="0", high="0", med="0", low="0"):
    context = {
        "{{ user_name }}": user_name,
        "{{ target_url }}": target_url,
        "{{ duration }}": duration,
        "{{ vulns_count }}": vulns_count,
        "{{ report_link }}": report_link,
        "{{ crit_count }}": crit,
        "{{ high_count }}": high,
        "{{ med_count }}": med,
        "{{ low_count }}": low
    }
    html = render_template('scan_completed.html', context)
    if html:
        _send_email_async(user_email, "Scan Completed Successfully", html)

def send_critical_alert(user_email, user_name, target_url, duration, vulns_count, report_link, crit="0", high="0", med="0", low="0"):
    context = {
        "{{ user_name }}": user_name,
        "{{ target_url }}": target_url,
        "{{ duration }}": duration,
        "{{ vulns_count }}": vulns_count,
        "{{ report_link }}": report_link,
        "{{ crit_count }}": crit,
        "{{ high_count }}": high,
        "{{ med_count }}": med,
        "{{ low_count }}": low
    }
    html = render_template('critical_alert.html', context)
    if html:
        _send_email_async(user_email, "🚨 URGENT: Critical Vulnerabilities Detected", html)

def send_scan_failed(user_email, user_name, target_url, scan_type, error_message):
    context = {
        "{{ user_name }}": user_name,
        "{{ target_url }}": target_url,
        "{{ scan_type }}": scan_type,
        "{{ error_message }}": error_message,
        "{{ dashboard_link }}": DASHBOARD_URL
    }
    html = render_template('scan_failed.html', context)
    if html:
        _send_email_async(user_email, "Scan Failed Alert", html)

def send_password_reset(user_email, user_name, reset_token):
    reset_link = f"{DASHBOARD_URL}/reset-password?token={reset_token}"
    context = {
        "{{ user_name }}": user_name,
        "{{ reset_link }}": reset_link
    }
    html = render_template('password_reset.html', context)
    if html:
        _send_email_async(user_email, "Password Reset Request", html)
