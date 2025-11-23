# app/utils/session_ui.py
import streamlit as st

def show_logout_button(sidebar: bool = True, label: str = "🚪 Logout"):
    """
    Show a logout button (sidebar by default). When clicked it clears session_state
    and triggers a rerun so the app returns to login.
    """
    target = st.sidebar if sidebar else st

    if "username" in st.session_state and st.session_state.get("username"):
        target.markdown(f"**Signed in as:** {st.session_state.get('username')}")

        if target.button(label):
            # clear only user-related session data
            for k in list(st.session_state.keys()):
                del st.session_state[k]

            st.session_state["just_logged_out"] = True

            # NEW: Streamlit v1.32+ uses st.rerun()
            st.rerun()
