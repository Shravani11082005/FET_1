"""
app/utils/auth.py
SQLite-backed auth helper that delegates to the DB layer (app.utils.db).
Fixed to avoid circular imports / name shadowing.
"""

from typing import Optional
import re

# import the db module to call functions without shadowing names
from app.utils import db as db_layer


# -------------------------------------------------------
# Registration (wrapper)
# -------------------------------------------------------
def register_user(username: str, email: str, password: str) -> bool:
    """
    Register a new user. Returns True on success, False on failure.
    Delegates to db_layer.create_user() which handles uniqueness and hashing.
    """
    username = (username or "").strip()
    email = (email or "").strip()
    password = (password or "")

    # basic validation
    if not username or not email or not password:
        return False

    # simple email validation (not strict)
    if "@" not in email or "." not in email.split("@")[-1]:
        return False

    # optional: enforce password strength
    if not strong_password(password):
        return False

    # delegate to DB (create_user returns True/False)
    return db_layer.create_user(username, email, password)


# -------------------------------------------------------
# Login (wrapper)
# -------------------------------------------------------
def check_login(username: str, password: str) -> bool:
    """
    Return True if username/password match.
    Delegates to db_layer.login_user which verifies hashes.
    """
    username = (username or "").strip()
    password = (password or "")
    if not username or not password:
        return False
    return db_layer.login_user(username, password)


# -------------------------------------------------------
# Email retrieval
# -------------------------------------------------------
def get_user_email_wrapper(username: str) -> Optional[str]:
    """
    Return the email for a given username (or None).
    Calls the DB-layer function directly to avoid name collisions.
    """
    if not username:
        return None
    return db_layer.get_user_email(username)


# -------------------------------------------------------
# Password strength check
# -------------------------------------------------------
def strong_password(pw: str) -> bool:
    """
    Minimal strength check: length >= 4, contains a digit and a non-alphanumeric character.
    Adjust rules as needed.
    """
    if not pw or len(pw) < 4:
        return False
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    return has_digit and has_symbol


# Backwards-compatible names (if other pages import these exact names)
check_login = check_login
get_user_email = get_user_email_wrapper
