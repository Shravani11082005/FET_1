import streamlit as st
from datetime import datetime

from app.utils.db import add_goal, delete_goal
from app.utils.budget import load_budget
from app.utils.goals_utils import load_goals


from utils.goals_utils import (
    load_goals,
    add_goal,
    delete_goal,
)

from app.utils.expenses import monthly_summary
from app.utils.family_utils import family_monthly_income
from app.utils.formatting import rupee


st.set_page_config(page_title="Goals", layout="wide")
st.title("🎯 Financial Goals")


# -------------------------------------------------------------------
# Ensure login
# -------------------------------------------------------------------
if "username" not in st.session_state or not st.session_state.username:
    st.warning("Please login first.")
    st.stop()

username = st.session_state.username


# -------------------------------------------------------------------
# Load current budget and savings for progress calculation
# -------------------------------------------------------------------
budget_info = load_budget(username)
main_budget = budget_info.get("main_budget")

if not main_budget:
    main_budget = family_monthly_income(username)

year = datetime.now().year
month = datetime.now().month
_, saved_this_month = monthly_summary(username, year, month, main_budget)


# -------------------------------------------------------------------
# Add New Goal
# -------------------------------------------------------------------
st.subheader("➕ Add a New Goal")

with st.form("add_goal_form", clear_on_submit=False):
    goal_name = st.text_input("Goal name")
    target_amount = st.number_input("Target amount (₹)", min_value=0.0, step=500.0)
    months_to_complete = st.number_input("Months to complete", min_value=1, step=1, value=6)

    if st.form_submit_button("Add Goal"):
        if not goal_name or target_amount <= 0:
            st.warning("Please enter a valid goal name and amount.")
        else:
            add_goal(username, goal_name, target_amount, int(months_to_complete))
            st.success("Goal added successfully!")
            st.rerun()


st.markdown("---")


# -------------------------------------------------------------------
# Show Existing Goals
# -------------------------------------------------------------------
st.subheader("📌 Your Goals")

goals_df = load_goals(username)

if goals_df.empty:
    st.info("No goals added yet.")
    st.stop()

for idx, row in goals_df.iterrows():

    # Calculate progress percentage
    target = float(row["target_amount"])
    months = int(row["months_to_complete"])
    monthly_required = target / months if months else target

    progress_pct = (saved_this_month / monthly_required) * 100 if monthly_required > 0 else 0
    progress_pct = min(progress_pct, 100)

    # UI layout
    box = st.container()
    with box:
        c1, c2 = st.columns([3, 1])

        with c1:
            st.markdown(f"### {row['goal_name']}")
            st.write(f"🎯 Target: {rupee(target)}")
            st.write(f"⏳ Duration: {months} months")

            st.progress(int(progress_pct))
            st.caption(f"Estimated progress this month: {progress_pct:.0f}%")

        with c2:
            if st.button("🗑 Delete", key=f"delete_{idx}"):
                delete_goal(username, row["goal_name"])
                st.success("Goal deleted!")
                st.rerun()

    st.markdown("---")
