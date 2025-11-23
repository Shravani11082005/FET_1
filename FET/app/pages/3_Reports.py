import streamlit as st
import pandas as pd
import json
from datetime import datetime

from utils.expenses import monthly_summary, yearly_summary, category_breakdown
from utils.db import (
    load_expenses,
    load_budget,
    load_goals,
)

from utils.family_utils import family_monthly_income
from utils.predictions import predict_next_month
from utils.formatting import rupee

import plotly.graph_objects as go


st.set_page_config(page_title="Reports", layout="wide")
st.title("📊 Reports & Insights")


# -------------------------------------------------------------------
# Ensure logged in
# -------------------------------------------------------------------
if "username" not in st.session_state or not st.session_state.username:
    st.warning("Please login first.")
    st.stop()

username = st.session_state.username


# -------------------------------------------------------------------
# Filters – Select Year & Month
# -------------------------------------------------------------------
current_year = datetime.now().year
current_month = datetime.now().month

col_y, col_m = st.columns([1, 1])

year = col_y.selectbox("Select Year", list(range(current_year - 5, current_year + 1)), index=5)
month = col_m.selectbox(
    "Select Month",
    list(range(1, 13)),
    index=current_month - 1
)


# -------------------------------------------------------------------
# Load budget & calculate summaries
# -------------------------------------------------------------------
budget_info = load_budget(username)
from utils.budget import load_budget

main_budget = budget_info.get("main_budget")

budget_info = load_budget(username)
main_budget = budget_info["main_budget"]
category_limits = json.loads(budget_info["category_limits_json"])

if not main_budget:
    main_budget = family_monthly_income(username)

spent, saved = monthly_summary(username, year, month, main_budget)
y_spent, y_saved = yearly_summary(username, year, main_budget)


# -------------------------------------------------------------------
# Summary boxes
# -------------------------------------------------------------------
st.subheader("📌 Summary")

c1, c2, c3 = st.columns(3)
c1.metric("Monthly Budget", rupee(main_budget))
c2.metric("Spent This Month", rupee(spent))
c3.metric("Saved This Month", rupee(saved))

st.markdown("---")


# -------------------------------------------------------------------
# Category breakdown (Bar Chart)
# -------------------------------------------------------------------
st.subheader("📦 Category Breakdown")

cat = category_breakdown(username, year, month)

# --- AUTO CATEGORY SAFETY PATCH ---
import pandas as pd
if isinstance(cat, dict):
    cat = pd.Series(cat)
if cat is None:
    cat = pd.Series(dtype=float)
if not isinstance(cat, pd.Series):
    try:
        cat = pd.Series(cat)
    except Exception:
        cat = pd.Series(dtype=float)
# --- END AUTO CATEGORY SAFETY PATCH ---


# --- AUTO CATEGORY SAFETY PATCH INSERTED ---
import pandas as pd

# If cat is a dict → Series
if isinstance(cat, dict):
    cat = pd.Series(cat)

# If None → empty Series
if cat is None:
    cat = pd.Series(dtype=float)

# If not a Series → attempt conversion
if not isinstance(cat, pd.Series):
    try:
        cat = pd.Series(cat)
    except Exception:
        cat = pd.Series(dtype=float)
# --- END CATEGORY SAFETY PATCH ---


if cat.empty:
    st.info("No expenses for this month.")
else:
    fig = go.Figure()
    fig.add_bar(x=cat.index.tolist(), y=cat.values.tolist())
    fig.update_layout(title="Category-wise Spending", height=300)
    st.plotly_chart(fig, width='stretch')


# -------------------------------------------------------------------
# Spending Trend (last 6 months) + Prediction
# -------------------------------------------------------------------
st.markdown("---")
st.subheader("📈 Trend & Prediction")

pred, lbls, vals = predict_next_month(username)

if pred is None:
    st.info("Not enough history to show trend & prediction.")
else:
    fig2 = go.Figure()

    # Historical data
    fig2.add_trace(
        go.Scatter(
            x=lbls,
            y=vals,
            mode="lines+markers",
            name="Last Months"
        )
    )

    # Prediction
    fig2.add_trace(
        go.Scatter(
            x=lbls + ["Next"],
            y=vals + [pred],
            mode="lines+markers",
            name="Prediction"
        )
    )

    fig2.update_layout(height=320)
    st.plotly_chart(fig2, width='stretch')

    st.success(f"Predicted spending next month: **{rupee(pred)}**")


# -------------------------------------------------------------------
# Yearly summary (for full year)
# -------------------------------------------------------------------
st.markdown("---")
st.subheader("📅 Yearly Summary")

c4, c5 = st.columns(2)
c4.metric("Total Spent This Year", rupee(y_spent))
c5.metric("Estimated Saved (Budget-based)", rupee(y_saved))

st.markdown("---")
st.info("Use Dashboard for more visual analytics and alerts.")
