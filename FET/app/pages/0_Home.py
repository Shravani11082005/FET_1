# pages/0_Home.py
import streamlit as st
from datetime import datetime
from utils.formatting import rupee, format_date
from utils.expenses import monthly_summary, load_expenses
from utils.budget import load_budget
from utils.family_utils import family_monthly_income

st.set_page_config(page_title="Home", page_icon="🏡", layout="wide")
st.title("🏡 Family Expense Tracker — Home")

# require login
if "username" not in st.session_state or not st.session_state.username:
    st.info("Welcome! Please login or register (use the sidebar pages).")
    st.markdown("If you're new, open the Register tab in the sidebar to create an account.")
    st.stop()

username = st.session_state.username

# quick stats
binfo = load_budget(username)
main_budget = binfo.get("main_budget")
if not main_budget:
    main_budget = family_monthly_income(username)

y = datetime.now().year
m = datetime.now().month
spent, saved = monthly_summary(username, y, m, main_budget)

col1, col2, col3 = st.columns([1.8, 1, 1])
with col1:
    st.markdown(f"### 👋 Hello, **{username}**")
    st.markdown("Plan together — Protect together — Prosper together.")
    st.markdown("---")
    st.markdown("Quick Actions")
    c1, c2, c3 = st.columns(3)
    if c1.button("📊 Dashboard"):
        st.query_params = {"page": "Dashboard"}
        st.rerun()
    if c2.button("➕ Add Expense"):
        st.query_params = {"page": "Add Expense"}
        st.rerun()
    if c3.button("⚙️ Settings"):
        st.query_params = {"page": "Settings"}
        st.rerun()

with col2:
    st.markdown("### Monthly Budget")
    st.metric("Budget", rupee(main_budget))
    st.metric("Spent", rupee(spent))

with col3:
    st.markdown("### This month")
    st.metric("Saved", rupee(saved))
    # most recent 3 transactions
    hist = load_expenses(username)
    if not hist.empty:
        hist["date"] = hist["date"].astype(str)
        recent = hist.sort_values("date", ascending=False).head(3)
        for _, r in recent.iterrows():
            st.write(f"- {r['date']} • {r['category']} • {rupee(r['amount'])}")

st.markdown("---")
st.caption(f"Logged in as {username} • {format_date(datetime.now())}")
