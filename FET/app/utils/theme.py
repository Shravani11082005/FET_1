# utils/theme.py
import streamlit as st

def apply_theme():
    """Apply global CSS/theme to the app. Call at top of pages or in app.py."""
    css = """
    <style>
    :root{
        --primary:#114a86;
        --accent:#f7caca;
        --card-bg: #ffffff;
        --muted:#6b7885;
    }
    /* page background */
    .stApp {
        background: linear-gradient(135deg, #fbfcfe 0%, #fffaf6 100%);
        font-family: Poppins, "Segoe UI", Roboto, "Helvetica Neue", Arial;
    }

    /* card look */
    .fetc-card {
        background: var(--card-bg);
        padding: 16px;
        border-radius: 12px;
        box-shadow: 0 8px 30px rgba(20,40,80,0.06);
        margin-bottom: 12px;
    }

    .fetc-title {
        color: var(--primary);
        font-weight: 700;
        margin-bottom: 8px;
    }

    /* full-width primary buttons */
    .fetc-btn {
        display:block;
        width:100%;
        padding:10px 12px;
        border-radius:12px;
        background:linear-gradient(90deg,var(--primary), #0d3a66);
        color:white !important;
        border:none;
    }

    /* small muted captions */
    .fetc-muted { color:var(--muted); font-size:13px; }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)
