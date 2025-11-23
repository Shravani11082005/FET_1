# app/utils/notify.py (debug version)
from app.utils.email import send_email_alert
from app.utils.db import send_telegram_alert
import traceback
import sys

def notify_user(user_email: str | None,
                telegram_chat_id: str | None,
                subject: str,
                message_text: str,
                message_html: str | None = None):

    print("DEBUG: notify_user called")
    print("  user_email:", user_email)
    print("  telegram_chat_id:", telegram_chat_id)
    print("  subject:", subject)
    # do not print message_html if very large, but we will show lengths
    print("  message_text (len):", len(message_text) if message_text else 0)
    print("  message_html (len):", len(message_html) if message_html else 0)
    sys.stdout.flush()

    results = {"telegram": None, "email": None}

    # ---- TELEGRAM ----
    try:
        print("DEBUG: calling send_telegram_alert(message_text)")
        sys.stdout.flush()
        t_ok = send_telegram_alert(message_text)
        print("DEBUG: send_telegram_alert returned:", t_ok)
        results["telegram"] = bool(t_ok)
    except Exception as e:
        print("Telegram notify failed: (exception)")
        traceback.print_exc()
        results["telegram"] = False

    # ---- EMAIL ----
    try:
        print("DEBUG: calling send_email_alert(...)")
        sys.stdout.flush()
        e_ok = None
        if user_email:
            e_ok = send_email_alert(
                to_email=user_email,
                subject=subject,
                body_plain=message_text,
                body_html=message_html or f"<p>{message_text}</p>"
            )
            print("DEBUG: send_email_alert returned:", e_ok)
            results["email"] = bool(e_ok)
        else:
            print("DEBUG: no user_email provided — skipping email")
            results["email"] = None
    except Exception as e:
        print("Email notify failed: (exception)")
        traceback.print_exc()
        results["email"] = False

    print("DEBUG: notify_user returning:", results)
    sys.stdout.flush()
    return results
