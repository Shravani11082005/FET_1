# app/utils/db.py
from __future__ import annotations
import sqlite3
import json
import time
import secrets
import hashlib
from pathlib import Path
from typing import Optional, Any, List, Dict

# Prefer bcrypt if available (safer). If not, fallback to SHA256 (less ideal).
try:
    import bcrypt  # type: ignore
    HAS_BCRYPT = True
except Exception:
    bcrypt = None
    HAS_BCRYPT = False

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent  # app/
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = INSTANCE_DIR / "app.db"

# Utilities
def get_conn() -> sqlite3.Connection:
    """
    Return a sqlite3.Connection configured to return sqlite3.Row rows.
    Use this connection for all DB operations in this module.
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Password hashing helpers ----------
def hash_password(plain: str) -> str:
    """
    Hash a password. Uses bcrypt if available, else SHA256 (fallback).
    Returns the hashed string.
    """
    if not plain:
        return ""
    if HAS_BCRYPT:
        hashed = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt())
        return hashed.decode("utf-8")
    # fallback: use SHA256 (not recommended for production)
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify plaintext against stored hash. Works with bcrypt or SHA256 fallback.
    """
    if not hashed:
        return False
    if HAS_BCRYPT:
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False
    return hashlib.sha256(plain.encode("utf-8")).hexdigest() == hashed

# ---------- Database bootstrap ----------
def init_db() -> None:
    """Create tables if they don't exist."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password_hash TEXT,
        reset_token TEXT,
        reset_expiry INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS family (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        member_name TEXT,
        relation TEXT,
        monthly_income REAL DEFAULT 0,
        age INTEGER DEFAULT 0,
        notes TEXT,
        is_head INTEGER DEFAULT 0,
        family_name TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        date TEXT,
        amount REAL,
        category TEXT,
        assigned_member TEXT,
        split_json TEXT,
        note TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        main_budget REAL,
        category_limits_json TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        goal_name TEXT,
        target_amount REAL,
        months_to_complete INTEGER,
        created_on TEXT
    )
    """)

    conn.commit()
    conn.close()

# ---------- User management ----------
def create_user(username: str, email: str, password: str) -> bool:
    """
    Create user with hashed password. Returns True on success, False on duplicate/error.
    """
    if not username or not password:
        return False
    try:
        pw_hash = hash_password(password)
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email or "", pw_hash)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        try:
            conn.close()
        except Exception:
            pass
        return False
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

# compatibility wrapper
def register_user(username: str, email: str, password: str) -> bool:
    return create_user(username, email, password)

def login_user(username: str, password: str) -> bool:
    """
    Return True if username/password match, False otherwise.
    """
    if not username or not password:
        return False
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    pw_hash = row["password_hash"] if "password_hash" in row.keys() else None
    return verify_password(password, pw_hash or "")

def get_user_email(username: str) -> Optional[str]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    val = row["email"] if "email" in row.keys() else None
    return val if val not in (None, "") else None

def get_username(username: str) -> Optional[str]:
    """
    Convenience: return username if user exists else None.
    (Some pages import get_username).
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return row["username"]

# ---------- Password reset tokens ----------
def create_reset_token(email_or_username: str, ttl_seconds: int = 3600) -> Optional[str]:
    """
    Create a reset token for a user identified by email or username.
    Returns token string (also stored on user row), or None if user not found.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ? OR email = ?", (email_or_username, email_or_username))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    username = row["username"]
    token = secrets.token_urlsafe(24)
    expiry = int(time.time()) + int(ttl_seconds)
    cur.execute("UPDATE users SET reset_token = ?, reset_expiry = ? WHERE username = ?", (token, expiry, username))
    conn.commit()
    conn.close()
    return token

# aliases to match older names in pages
generate_reset_token = create_reset_token

def verify_reset_token(token: str) -> Optional[str]:
    """Return username if token valid and not expired, else None."""
    if not token:
        return None
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, reset_expiry FROM users WHERE reset_token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    username, expiry = row["username"], row["reset_expiry"]
    try:
        expiry = int(expiry) if expiry else 0
    except Exception:
        expiry = 0
    if expiry and time.time() > expiry:
        return None
    return username

# alias older name
validate_reset_token = verify_reset_token

def clear_reset_token(username: str) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET reset_token = NULL, reset_expiry = NULL WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def reset_password(username: str, new_password: str) -> bool:
    try:
        new_hash = hash_password(new_password)
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL, reset_expiry = NULL WHERE username = ?",
            (new_hash, username)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

# ---------- Family helpers ----------
def add_family_member(username: str,
                      member_name: str,
                      relation: str,
                      monthly_income: Optional[float] = None,
                      age: int = 0,
                      notes: str = "",
                      is_head: bool = False,
                      family_name: str = "",
                      **kwargs) -> bool:
    """
    Insert one family member. Returns True on success.
    Accepts legacy kw 'income' mapped to monthly_income.
    """
    if monthly_income is None and "income" in kwargs:
        try:
            monthly_income = float(kwargs.get("income", 0.0) or 0.0)
        except Exception:
            monthly_income = 0.0
    try:
        monthly_income = float(monthly_income or 0.0)
    except Exception:
        monthly_income = 0.0
    try:
        age = int(age or 0)
    except Exception:
        age = 0

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO family (
                username, member_name, relation, monthly_income,
                age, notes, is_head, family_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username,
            member_name or "",
            relation or "",
            monthly_income,
            age,
            notes or "",
            1 if is_head else 0,
            family_name or ""
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

def save_family(family_name: str, username: str, rows: List[Dict]) -> bool:
    """
    Replace all family members for a user with provided rows (list of dicts).
    Each dict should contain keys: member_name, relation, monthly_income, age, notes, is_head.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM family WHERE username = ?", (username,))
        for r in rows:
            try:
                monthly_income = float(r.get("monthly_income") or 0.0)
            except Exception:
                monthly_income = 0.0
            try:
                age = int(r.get("age") or 0)
            except Exception:
                age = 0
            cur.execute("""
                INSERT INTO family (
                    username, member_name, relation, monthly_income, age, notes, is_head, family_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                str(r.get("member_name") or ""),
                str(r.get("relation") or ""),
                monthly_income,
                age,
                str(r.get("notes") or ""),
                1 if str(r.get("is_head","")).lower() in ("on","true","1","yes") else 0,
                family_name or ""
            ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

def load_family(username: str) -> List[Dict]:
    """
    Return list of dicts for family members.
    Each dict keys: id, member_name, relation, monthly_income, age, notes, is_head, family_name
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, member_name, relation, monthly_income, age, notes, is_head, family_name
        FROM family WHERE username = ?
        ORDER BY id ASC
    """, (username,))
    rows = cur.fetchall()
    conn.close()
    result: List[Dict] = []
    for r in rows:
        row_map = {k: r[k] for k in r.keys()}
        result.append(row_map)
    return result

def delete_family_member(username: str, member_identifier: Any) -> bool:
    """
    Delete family member by id (int or numeric string) or by member_name (str).
    Returns True if deleted.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        if isinstance(member_identifier, int) or (isinstance(member_identifier, str) and member_identifier.isdigit()):
            mid = int(member_identifier)
            cur.execute("DELETE FROM family WHERE username = ? AND id = ?", (username, mid))
        else:
            cur.execute("DELETE FROM family WHERE username = ? AND member_name = ?", (username, str(member_identifier)))
        conn.commit()
        rc = cur.rowcount
        conn.close()
        return rc > 0
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

# ---------- Expenses ----------
def add_expense(username: str,
                amount: Any,
                category: str,
                assigned_member: str = "",
                split: Optional[Any] = None,
                note: str = "",
                date: Optional[str] = None) -> bool:
    """
    Adds an expense row. split can be dict/list/None. date default = today's date (YYYY-MM-DD).
    """
    try:
        if date is None:
            date = time.strftime("%Y-%m-%d")
        try:
            amount_val = float(amount)
        except Exception:
            amount_val = 0.0

        if split is None:
            split_json = ""
        else:
            try:
                split_json = json.dumps(split)
            except Exception:
                split_json = ""

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO expenses (username, date, amount, category, assigned_member, split_json, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, date, amount_val, category or "", assigned_member or "", split_json, note or ""))
        conn.commit()
        conn.close()
        return True
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

def load_expenses(username: str) -> List[Dict]:
    """
    Load expenses for a user and return list of dicts.
    Each dict includes 'split' parsed from split_json.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, date, amount, category, assigned_member, split_json, note
        FROM expenses WHERE username = ?
        ORDER BY date DESC, id DESC
    """, (username,))
    rows = cur.fetchall()
    conn.close()
    result: List[Dict] = []
    for r in rows:
        row_map = {k: r[k] for k in r.keys()}
        sj = row_map.get("split_json") or ""
        try:
            parsed = json.loads(sj) if sj else None
        except Exception:
            parsed = None
        row_map["split"] = parsed
        result.append(row_map)
    return result

# ---------- Budgets ----------
def set_budget(username: str, main_budget: Any, category_limits: Any = None) -> bool:
    """
    Store per-user budget (replaces previous entries). category_limits stored as JSON string.
    """
    try:
        try:
            mb_val = float(main_budget) if main_budget not in (None, "") else None
        except Exception:
            mb_val = None

        if category_limits is None:
            cat_json = "{}"
        elif isinstance(category_limits, str):
            try:
                json.loads(category_limits)
                cat_json = category_limits
            except Exception:
                cat_json = "{}"
        else:
            try:
                cat_json = json.dumps(category_limits)
            except Exception:
                cat_json = "{}"

        conn = get_conn()
        cur = conn.cursor()
        # delete old (we maintain a single latest row per user)
        cur.execute("DELETE FROM budgets WHERE username = ?", (username,))
        cur.execute(
            "INSERT INTO budgets (username, main_budget, category_limits_json) VALUES (?, ?, ?)",
            (username, mb_val if mb_val is not None else None, cat_json)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

def load_budget(username: str) -> Dict[str, Any]:
    """
    Return dict: {'main_budget': float|None, 'category_limits_json': str}
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT main_budget, category_limits_json FROM budgets WHERE username = ? ORDER BY id DESC LIMIT 1", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {"main_budget": None, "category_limits_json": "{}"}
    main = row["main_budget"]
    cat_json = row["category_limits_json"] or "{}"
    try:
        main_val = float(main) if main not in (None, "") else None
    except Exception:
        main_val = None
    return {"main_budget": main_val, "category_limits_json": cat_json}

# Convenience alias names for older pages
append_expense = add_expense
db_load_budget = load_budget

# ---------- Goals ----------
def add_goal(username: str,
             goal_name: str,
             target_amount: float,
             months: int,
             created_on: Optional[str] = None) -> bool:
    """
    Insert a goal. created_on is optional; if not provided we set today's date (YYYY-MM-DD).
    Returns True on success, False on failure.
    """
    try:
        if created_on is None:
            created_on = time.strftime("%Y-%m-%d")
        else:
            # normalize to YYYY-MM-DD if possible (leave as-is on parse failure)
            try:
                # if created_on is a timestamp (int) or float, convert
                if isinstance(created_on, (int, float)):
                    created_on = time.strftime("%Y-%m-%d", time.localtime(int(created_on)))
                else:
                    # try parsing common formats and reformat
                    from datetime import datetime
                    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
                        try:
                            dt = datetime.strptime(str(created_on), fmt)
                            created_on = dt.strftime("%Y-%m-%d")
                            break
                        except Exception:
                            continue
            except Exception:
                # fallback: keep original value
                pass

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO goals (username, goal_name, target_amount, months_to_complete, created_on) VALUES (?, ?, ?, ?, ?)",
            (username, goal_name or "", float(target_amount or 0.0), int(months or 1), created_on)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

def load_goals(username: str) -> List[Dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, goal_name, target_amount, months_to_complete, created_on FROM goals WHERE username = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    conn.close()
    result: List[Dict] = []
    for r in rows:
        result.append({k: r[k] for k in r.keys()})
    return result

def delete_goal(username: str, goal_identifier: Any) -> bool:
    try:
        conn = get_conn()
        cur = conn.cursor()
        if isinstance(goal_identifier, int) or (isinstance(goal_identifier, str) and goal_identifier.isdigit()):
            gid = int(goal_identifier)
            cur.execute("DELETE FROM goals WHERE username = ? AND id = ?", (username, gid))
        else:
            cur.execute("DELETE FROM goals WHERE username = ? AND goal_name = ?", (username, str(goal_identifier)))
        conn.commit()
        rc = cur.rowcount
        conn.close()
        return rc > 0
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False

# ---------- Analytics helper ----------
def category_breakdown(username: str, year: int, month: int) -> Dict[str, float]:
    """
    Returns a dict mapping category -> total_spent for the given username and year/month.
    Example: {'Rent': 12000.0, 'Groceries': 4000.0}
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT category, SUM(amount) as total
        FROM expenses
        WHERE username = ?
          AND substr(date, 1, 4) = ?
          AND substr(date, 6, 2) = ?
        GROUP BY category
        """,
        (username, str(year), f"{int(month):02d}")
    )
    rows = cur.fetchall()
    conn.close()
    out: Dict[str, float] = {}
    for r in rows:
        cat = r["category"] or "Other"
        total = float(r["total"] or 0.0)
        out[cat] = total
    return out

# Run DB init on import (safe)
try:
    init_db()
except Exception:
    # swallow import-time init errors; caller can call init_db explicitly
    pass

# ============================
# 🔔 TELEGRAM + EMAIL ALERTS
# ============================

import json, os, requests
from datetime import datetime

# ---- Load Telegram Config ----
def load_telegram_config():
    cfg_path = os.path.join(BASE_DIR, "instance", "telegram_config.json")
    if not os.path.exists(cfg_path):
        return {"bot_token": "", "chat_id": ""}

    with open(cfg_path, "r") as f:
        return json.load(f)


# ---- Send Telegram Message ----
def send_telegram_alert(message: str) -> bool:
    try:
        cfg = load_telegram_config()
        token = cfg.get("bot_token", "").strip()
        chat_id = cfg.get("chat_id", "").strip()

        if not token or not chat_id:
            print("Telegram config missing.")
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        r = requests.post(url, data={"chat_id": chat_id, "text": message}, timeout=10)

        return r.status_code == 200

    except Exception as e:
        print("Telegram send error:", e)
        return False


# ==================================
# 📧 EMAIL ALERTS (SMTP)
# ==================================

import smtplib
from email.mime.text import MIMEText

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = os.environ.get("SMTP_PORT")
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")

def send_email_alert(to_addr: str, subject: str, body: str) -> bool:
    try:
        if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
            print("SMTP NOT CONFIGURED")
            return False

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = to_addr

        with smtplib.SMTP_SSL(SMTP_HOST, int(SMTP_PORT)) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_addr, msg.as_string())

        return True

    except Exception as e:
        print("Email send error:", e)
        return False

# ==================================
# 🚨 Combined Budget Alert Function
# ==================================

def send_budget_alert(username: str, category: str, spent: float, limit: float):
    message = (
        f"⚠️ Budget Alert!\n"
        f"User: {username}\n"
        f"Category: {category}\n"
        f"Spent: ₹{spent}\n"
        f"Limit: ₹{limit}\n"
        f"Status: {'OVER LIMIT' if spent >= limit else 'NEAR LIMIT'}\n"
        f"Time: {datetime.now()}"
    )

    # Telegram Alert
    send_telegram_alert(message)

    # Email Alert
    to_addr = get_user_email(username)
    if to_addr:
        send_email_alert(to_addr, f"Budget Alert: {category}", message)

# ------------------------------------------------------------
# 🔥 ADD THESE NOTIFICATION HELPER FUNCTIONS (Final Version)
# ------------------------------------------------------------
def get_user_budget(username: str):
    """
    Return user's monthly budget.
    Uses: load_budget(username) -> {"main_budget": value}
    """
    try:
        b = load_budget(username)
        if not b:
            return None
        return b.get("main_budget")  # budget stored as "main_budget"
    except Exception:
        return None


def get_user_contacts(username: str):
    """
    Returns (email, telegram_chat_id)

    email -> from users table
    telegram_chat_id -> from instance/telegram_users.json if exists
                        else from telegram_config.json (global fallback)
                        else None
    """
    # 1. email from DB
    try:
        email = get_user_email(username)
    except Exception:
        email = None

    telegram_chat_id = None

    # 2. Try per-user Telegram mapping
    try:
        user_map_path = os.path.join(BASE_DIR, "instance", "telegram_users.json")
        if os.path.exists(user_map_path):
            with open(user_map_path, "r") as f:
                data = json.load(f)
            telegram_chat_id = data.get(username)
    except Exception:
        pass

    # 3. Fallback: global telegram_config.json
    if not telegram_chat_id:
        try:
            cfg = load_telegram_config()
            telegram_chat_id = cfg.get("chat_id", "")
            if not telegram_chat_id.strip():
                telegram_chat_id = None
        except Exception:
            telegram_chat_id = None

    return (email, telegram_chat_id)


def get_monthly_family_expenses(username: str):
    """
    Sums EXPENSES for current month for the given USERNAME.
    Uses the expenses table: expenses(username, amount, date,...)

    date format is stored as YYYY-MM-DD (your app uses st.date_input)
    """
    from datetime import datetime
    now = datetime.now()
    year = str(now.year)
    month = f"{now.month:02d}"

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT IFNULL(SUM(amount), 0) AS total
            FROM expenses
            WHERE username = ?
            AND substr(date, 1, 4) = ?
            AND substr(date, 6, 2) = ?
            """,
            (username, year, month)
        )
        row = cur.fetchone()
        conn.close()
        if row:
            return float(row["total"])
    except Exception:
        try:
            conn.close()
        except:
            pass

    return 0.0
# ------------------------------------------------------------
