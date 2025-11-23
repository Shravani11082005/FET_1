import streamlit as st
from utils.db import verify_reset_token, clear_reset_token, reset_password

st.title("🔐 Reset Your Password")

token = st.query_params.get("token", "")

if not token:
    st.error("Invalid reset link.")
    st.stop()

email = verify_reset_token(token)

if not email:
    st.error("Token invalid or expired.")
    st.stop()

st.success(f"Resetting password for: {email}")

new_pw = st.text_input("New password", type="password")
confirm_pw = st.text_input("Confirm password", type="password")

if st.button("Update password"):
    if new_pw != confirm_pw:
        st.error("Passwords do not match.")
        st.stop()

    if len(new_pw) < 4:
        st.warning("Password too short.")
        st.stop()

    if reset_password(email, new_pw):
        clear_reset_token(email)
        st.success("Password updated successfully!")
        st.info("Go back and login.")
    else:
        st.error("Failed to update password.")
