import streamlit as st
from utils.db import create_reset_token, get_user_email
from utils.email_utils import send_email  # if you use SMTP

st.title("🔑 Forgot Password")

st.write("Enter your registered username. A reset link will be emailed to you.")

username = st.text_input("Username")

if st.button("Send reset link"):
    if not username:
        st.warning("Enter your username.")
        st.stop()

    email = get_user_email(username)
    if not email:
        st.error("No user found with this username.")
        st.stop()

    token = create_reset_token(email)
    reset_url = f"http://localhost:8501/100_Reset_Password?token={token}"

    body = f"""
Hello,

Use the link below to reset your password:

{reset_url}

This link expires in 1 hour.
    """

    send_email(email, "Password Reset Link", body)

    st.success("Reset link sent to your email.")
