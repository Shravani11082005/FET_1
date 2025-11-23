import os, smtplib, requests, json
from email.message import EmailMessage

def send_email(to_email, subject, body):
    host = os.environ.get("FET_SMTP_HOST")
    port = os.environ.get("FET_SMTP_PORT")
    user = os.environ.get("FET_SMTP_USER")
    pwd  = os.environ.get("FET_SMTP_PASS")
    from_addr = os.environ.get("FET_FROM_EMAIL") or user
    if not (host and port):
        return False
    try:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, int(port), timeout=15) as smtp:
            try:
                smtp.starttls()
            except:
                pass
            if user and pwd:
                smtp.login(user, pwd)
            smtp.send_message(msg)
        return True
    except Exception:
        return False

def send_telegram_message(text, cfg):
    if not cfg.get("enabled"):
        return False
    token = cfg.get("bot_token"); chat_id = cfg.get("chat_id")
    if not token or not chat_id:
        return False
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", data={"chat_id":chat_id,"text":text})
        return r.status_code == 200
    except:
        return False
