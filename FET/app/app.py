# put this at the very top of app/app.py (first lines)
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
load_dotenv()

# top of app/app.py — replace the import block with this
from datetime import datetime, date
import streamlit as st
import time

from app.utils.db import (
    init_db,
    create_user,
    login_user,
    create_reset_token,
    verify_reset_token,
    clear_reset_token,
    reset_password,
    add_expense as db_add_expense,
    set_budget as db_set_budget,
    load_budget as db_load_budget,
    add_goal as db_add_goal,
    load_goals as db_load_goals,
    add_family_member as db_add_family_member,
    load_family as db_load_family,
    save_family as db_save_family
)

# import higher-level helpers from their correct modules
from app.utils.expenses import load_expenses, monthly_summary, yearly_summary, category_breakdown
from app.utils.family_utils import load_family as family_load_df, family_monthly_income
from app.utils.budget import load_budget, get_category_limit


# Initialize DB/tables (safe to call repeatedly)
init_db()

# Page config
st.set_page_config(page_title="Family Expense Tracker", page_icon="💖", layout="wide")

# Minimal splash (0.8s)
if "splash_done" not in st.session_state:
    placeholder = st.empty()
    placeholder.markdown(
        """
        <div style="padding:32px;text-align:center;">
          <div style="font-size:48px;animation:beat 1s infinite">💖</div>
          <div style="font-weight:700;color:#16466f;font-size:18px;margin-top:8px;">Family Expense Tracker</div>
          <div style="color:#556b82;font-size:13px;margin-top:6px;">Loading...</div>
        </div>
        <style>@keyframes beat{0%{transform:scale(1)}25%{transform:scale(1.12)}50%{transform:scale(1)}75%{transform:scale(1.12)}100%{transform:scale(1)}}</style>
        """,
        unsafe_allow_html=True,
    )
    time.sleep(0.8)
    placeholder.empty()
    st.session_state.splash_done = True

# If user already logged in, redirect to Home page
if "username" in st.session_state and st.session_state.username:
    st.info("Already signed in — redirecting...")
    time.sleep(0.2)
    st.switch_page("pages/0_Home.py")

# Small CSS for nicer inputs/cards
st.markdown(
    """
    <style>
      .card { background: #ffffff; padding:20px; border-radius:10px; box-shadow:0 6px 18px rgba(20,40,80,0.06); }
      .center { max-width:720px; margin-left:auto; margin-right:auto; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<div class='center'>", unsafe_allow_html=True)
st.markdown("<h1 style='text-align:center;color:#114a86;'>💸 Family Expense Tracker</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;color:#486676;'>Sign in or create an account to continue</p>", unsafe_allow_html=True)

tabs = st.tabs(["Login 🔐", "Register 🆕", "Forgot Password ❓"])

# -------------------------
# LOGIN TAB
# -------------------------
with tabs[0]:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("Login")
    login_user_input = st.text_input("Username", key="login_username")
    login_pass_input = st.text_input("Password", type="password", key="login_password")

    if st.button("Login", key="login_btn"):
        if not login_user_input or not login_pass_input:
            st.warning("Enter username and password.")
        else:
            ok = login_user(login_user_input, login_pass_input)
            if ok:
                st.session_state.username = login_user_input
                st.success("Login successful — redirecting to Home...")
                time.sleep(0.4)
                st.switch_page("pages/0_Home.py")
            else:
                st.error("Invalid username or password.")
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------
# REGISTER TAB
# -------------------------
with tabs[1]:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("Create an account")

    reg_username = st.text_input("Choose username", key="reg_username")
    reg_email = st.text_input("Email address", key="reg_email")
    reg_password = st.text_input("Password", type="password", key="reg_password")
    reg_confirm = st.text_input("Confirm password", type="password", key="reg_confirm")

    def password_strength(pw: str) -> bool:
        if not pw or len(pw) < 4:
            return False
        has_digit = any(c.isdigit() for c in pw)
        has_symbol = any(not c.isalnum() for c in pw)
        return has_digit and has_symbol and len(pw) >= 4

    if reg_password:
        if password_strength(reg_password):
            st.success("Password strength: good ✅")
        else:
            st.info("Password should have ≥4 chars, include a number and a symbol.")

    if st.button("Create account", key="reg_btn"):
        if not reg_username or not reg_email or not reg_password:
            st.warning("All fields are required.")
        elif reg_password != reg_confirm:
            st.error("Passwords do not match.")
        elif not password_strength(reg_password):
            st.error("Password too weak.")
        else:
            ok = register_user(reg_username, reg_email, reg_password)
            if ok:
                st.success("Account created. You can now log in.")
                # optionally auto-login:
                st.session_state.username = reg_username
                time.sleep(0.4)
                st.switch_page("pages/0_Home.py")
            else:
                st.error("Username or email already exists.")
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------
# FORGOT PASSWORD TAB
# -------------------------
with tabs[2]:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("Forgot Password")

    fp_mode = st.radio("Choose action", ["Send reset token", "Reset using token"], index=0)

    if fp_mode == "Send reset token":
        fp_username = st.text_input("Enter your username", key="fp_username")
        if st.button("Send reset token", key="fp_send"):
            if not fp_username:
                st.warning("Enter username.")
            else:
                # find email
                email = get_user_email(fp_username)
                if not email:
                    st.error("User or email not found.")
                else:
                    token = create_reset_token(fp_username)
                    # For local testing we show token — in production you'd email a reset link
                    st.success("Reset token created.")
                    st.code(token, language="")
                    st.info("Use the token in the 'Reset using token' mode or via the emailed link.")
    else:
        # Reset using token
        token_input = st.text_input("Enter reset token", key="fp_token")
        new_pass = st.text_input("New Password", type="password", key="fp_new_pass")
        confirm_pass = st.text_input("Confirm Password", type="password", key="fp_confirm_pass")

        if st.button("Reset password", key="fp_reset"):
            if not token_input or not new_pass:
                st.warning("Provide token and new password.")
            elif new_pass != confirm_pass:
                st.error("Passwords do not match.")
            elif not password_strength(new_pass):
                st.error("Password too weak.")
            else:
                username = verify_reset_token(token_input)
                if not username:
                    st.error("Invalid or expired token.")
                else:
                    # Perform the password update here (use bcrypt directly)
                    import sqlite3, bcrypt
                    conn = sqlite3.connect(Path(__file__).resolve().parent.parent / "users.db")
                    cur = conn.cursor()
                    pw_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
                    cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pw_hash, username))
                    conn.commit()
                    conn.close()
                    clear_reset_token(token_input)
                    st.success("Password reset successful — please log in.")
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

# Final note: if server was started with reset token in query params, support quick flow
q = st.query_params
if q.get("reset_token"):
    # pre-fill token tab
    token = q.get("reset_token")
    # ensure string
    if isinstance(token, list):
        token = token[0]
    st.query_params = {}  # clear param
    st.info("Detected reset_token in link — open Forgot Password and choose 'Reset using token' and paste it.")
