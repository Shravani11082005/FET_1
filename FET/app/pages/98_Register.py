import streamlit as st
from utils.db import register_user
import re

st.set_page_config(page_title="Register", page_icon="📝")


# ---------------------------
# Password strength evaluator
# ---------------------------
def check_strength(pw: str) -> str:
    if len(pw) < 4:
        return "❌ Too short"

    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)

    if has_digit and has_symbol:
        return "✅ Strong"
    return "⚠️ Weak (add number & symbol)"


# ---------------------------
# UI Layout
# ---------------------------
st.markdown(
    """
    <div style='padding: 20px; text-align:center'>
        <h2 style='color:#114a86; font-weight:700;'>Create Your Account</h2>
        <p style='color:#3c5166;'>Start managing your expenses with your personal Family Tracker account</p>
    </div>
    """,
    unsafe_allow_html=True
)

# Center card
card = st.container()
with card:
    st.markdown(
        """
        <div style='background:white; padding:25px; border-radius:12px; 
                    box-shadow:0 4px 20px rgba(0,0,0,0.08); max-width:420px; margin:auto;'>
        """,
        unsafe_allow_html=True
    )

username = st.text_input("Username", placeholder="Choose a unique name")

email = st.text_input("Email", placeholder="you@example.com")

password = st.text_input("Password", type="password", placeholder="Min 4 chars incl. number & symbol")

# Strength indicator
if password:
    strength = check_strength(password)
    st.caption(f"Password Strength: **{strength}**")

st.markdown("<br>", unsafe_allow_html=True)

register_btn = st.button("Create Account", width='stretch')

if register_btn:
    if not username or not email or not password:
        st.error("All fields are required.")
    elif check_strength(password).startswith("❌"):
        st.error("Password too weak.")
    else:
        success = register_user(username, email, password)
        if success:
            st.success("Account created successfully! Redirecting to Login...")
            st.info("Go to **Home → Login** to sign in.")
        else:
            st.error("Username or Email already exists.")

st.markdown("</div>", unsafe_allow_html=True)
