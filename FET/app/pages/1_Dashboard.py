import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

from app.utils.db import (
    load_budget,
    category_breakdown,
    load_expenses,
    load_goals,
)

from app.utils.session_ui import show_logout_button
show_logout_button()  # put this near top of page (after imports)

st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")

# -------------------------------------------------
# USER SESSION
# -------------------------------------------------
username = st.session_state.get("username", "")
if not username:
    st.warning("Please login from the sidebar.")
    st.stop()

# -------------------------------------------------
# PAGE TITLE
# -------------------------------------------------
st.markdown("<h1>📊 Dashboard</h1>", unsafe_allow_html=True)

# -------------------------------------------------
# LOAD BUDGET & EXPENSE DATA
# -------------------------------------------------
now = datetime.now()
y = now.year
m = now.month

budget = load_budget(username) or {}
cat_spend = category_breakdown(username, y, m) or {}
expenses = load_expenses(username) or []
goals = load_goals(username) or []

# -------------------------------------------------
# SAFETY HELPERS
# -------------------------------------------------
def safe_float(value, default=0.0):
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)

import json
# budget.get(...) may fail if budget is None, thus budget is set to {} above
main_budget = safe_float(budget.get("main_budget", 0))
try:
    category_limits = json.loads(budget.get("category_limits_json") or "{}")
    if not isinstance(category_limits, dict):
        category_limits = {}
except Exception:
    category_limits = {}

monthly_spent = sum([safe_float(v, 0.0) for v in cat_spend.values()]) if cat_spend else 0.0
monthly_saved = main_budget - monthly_spent if main_budget > 0 else 0.0

# -------------------------------------------------
# BUDGET ALERTS
# -------------------------------------------------
def render_alerts():
    alerts = []

    for cat, limit in category_limits.items():
        limit_val = safe_float(limit, 0.0)
        spent_val = safe_float(cat_spend.get(cat, 0), 0.0)

        if limit_val <= 0:
            continue

        pct = (spent_val / limit_val) * 100 if limit_val else 0

        if pct >= 100:
            alerts.append(f"🔴 **{cat}** exceeded limit ({pct:.1f}%).")
        elif pct >= 80:
            alerts.append(f"⚠️ **{cat}** nearing limit ({pct:.1f}%).")

    if alerts:
        st.markdown("### ⚠️ Budget Alerts")
        for a in alerts:
            st.error(a)
    else:
        st.markdown("### 🟢 Budget Alerts")
        st.success("No category alerts! 🎉 You're within limits.")


render_alerts()

# -------------------------------------------------
# SUMMARY CARDS
# -------------------------------------------------
col1, col2, col3 = st.columns(3)

col1.metric("Monthly Budget", f"₹ {main_budget:,.2f}")
col2.metric("Monthly Spent", f"₹ {monthly_spent:,.2f}")
col3.metric("Monthly Saved", f"₹ {monthly_saved:,.2f}")

# -------------------------------------------------
# CHARTS SECTION
# -------------------------------------------------
st.markdown("---")
st.subheader("📈 This Month")

# BAR CHART – category spending
if cat_spend:
    df_chart = pd.DataFrame({
        "Category": list(cat_spend.keys()),
        "Amount": [safe_float(v, 0.0) for v in cat_spend.values()]
    })

    fig_bar = px.bar(
        df_chart,
        x="Category",
        y="Amount",
        title="Category-wise spending",
        labels={"Amount": "₹"},
    )
    st.plotly_chart(fig_bar, use_container_width=True)
else:
    st.info("No expenses recorded this month.")

# PIE CHART – spend % breakdown
if cat_spend:
    fig_pie = px.pie(
        df_chart,
        names="Category",
        values="Amount",
        title="Spending Distribution",
    )
    st.plotly_chart(fig_pie, use_container_width=True)

# -------------------------------------------------
# RECENT TRANSACTIONS
# -------------------------------------------------
st.markdown("---")
st.subheader("📄 Recent Transactions")

if expenses:
    df = pd.DataFrame(expenses)
    st.dataframe(df, use_container_width=True)
else:
    st.info("No transactions yet.")

# -------------------------------------------------
# ACTIVE GOALS (if exists)
# -------------------------------------------------
st.markdown("---")
st.subheader("🎯 Active Goal")

if goals:
    g = goals[-1]
    # guard access to keys
    goal_name = g.get("goal_name") if isinstance(g, dict) else str(g)
    target_amount = safe_float(g.get("target_amount", 0)) if isinstance(g, dict) else 0.0
    st.markdown(f"**{goal_name}** → ₹ **{target_amount:,.0f}**")
else:
    st.info("No goals yet.")
