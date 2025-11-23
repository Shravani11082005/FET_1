# app/utils/email.py
import os
import smtplib
from email.message import EmailMessage

def send_email_alert(to_email: str, subject: str, body_plain: str, body_html: str | None = None) -> bool:
    """
    Send an email using SMTP credentials from environment variables.
    Returns True on success, False on failure.
    """
    smtp_host = os.getenv("EMAIL_SMTP_HOST")
    smtp_port = int(os.getenv("EMAIL_SMTP_PORT", "587"))
    smtp_user = os.getenv("EMAIL_SMTP_USER")
    smtp_pass = os.getenv("EMAIL_SMTP_PASS")
    from_name = os.getenv("EMAIL_FROM_NAME", "")
    from_addr = smtp_user

    if not all([smtp_host, smtp_port, smtp_user, smtp_pass, to_email]):
        # Missing config or recipient
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"] = to_email
    msg.set_content(body_plain)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        # Use STARTTLS (port 587) or SSL (port 465)
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        return True
    except Exception as e:
        # replace with your project's logger if available
        print(f"[send_email_alert] failed: {e}")
        return False
