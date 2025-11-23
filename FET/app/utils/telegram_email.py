import os
import json
import requests
import smtplib
from email.message import EmailMessage
from pathlib import Path
from .storage import TELEGRAM_CFG, load_json, save_json


# ---------------------------------------------------------
# Telegram Configuration
# ---------------------------------------------------------

def load_telegram_config():
    # Prefer environment variables
    bot = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    enabled = os.environ.get("TELEGRAM_ENABLED", "").lower() == "true"

    if bot and chat:
        return {"bot_token": bot, "chat_id": chat, "enabled": enabled}

    # Fallback: local config
    cfg = load_json(TELEGRAM_CFG)
    return {
        "bot_token": cfg.get("bot_token", ""),
        "chat_id": str(cfg.get("chat_id", "")),
        "enabled": bool(cfg.get("enabled", False)),
    }


def save_telegram_config(cfg: dict):
    save_json(TELEGRAM_CFG, cfg)


# ---------------------------------------------------------
# Telegram Sending
# ---------------------------------------------------------

def send_telegram_message(text: str, cfg: dict | None = None) -> bool:
    if cfg is None:
        cfg = load_telegram_config()

    bot = cfg.get("bot_token", "")
    chat = cfg.get("chat_id", "")
    enabled = cfg.get("enabled", False)

    if not enabled or not bot or not chat:
        return False

    try:
        r = requests.post(
            f"https://api.telegram.org/bot{bot}/sendMessage",
            data={"chat_id": chat, "text": text, "parse_mode": "Markdown"},
            timeout=10
        )
        return r.status_code == 200 and r.json().get("ok")
    except:
        return False


# ---------------------------------------------------------
# Email Sending
# ---------------------------------------------------------

def send_email(to_email: str, subject: str, body: str) -> bool:
    if not to_email:
        return False

    host = os.environ.get("FET_SMTP_HOST", "")
    port = int(os.environ.get("FET_SMTP_PORT", "587"))
    user = os.environ.get("FET_SMTP_USER", "")
    passwd = os.environ.get("FET_SMTP_PASS", "")
    from_addr = os.environ.get("FET_FROM_EMAIL", user)

    try:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(host, port, timeout=15) as smtp:
            try:
                smtp.starttls()
            except:
                pass

            if user and passwd:
                try:
                    smtp.login(user, passwd)
                except:
                    pass

            smtp.send_message(msg)

        return True
    except:
        return False
