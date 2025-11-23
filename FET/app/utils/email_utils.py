# utils/email_utils.py
import smtplib
from email.message import EmailMessage
import os

SMTP_HOST = os.environ.get("FET_SMTP_HOST", "") or os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("FET_SMTP_PORT", "587") or os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("FET_SMTP_USER", "") or os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("FET_SMTP_PASS", "") or os.environ.get("SMTP_PASS", "")
FROM_EMAIL = os.environ.get("FET_FROM_EMAIL", SMTP_USER) or os.environ.get("SMTP_FROM", SMTP_USER)


def send_email(to_email: str, subject: str, body: str) -> bool:
    try:
        msg = EmailMessage()
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            try:
                smtp.starttls()
            except Exception:
                pass
            if SMTP_USER and SMTP_PASS:
                try:
                    smtp.login(SMTP_USER, SMTP_PASS)
                except Exception:
                    pass
            smtp.send_message(msg)

        return True
    except Exception as e:
        print("send_email error:", e)
        return False
