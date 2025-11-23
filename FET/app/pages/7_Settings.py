import streamlit as st
from utils.db import load_budget, set_budget
import json

st.set_page_config(layout="wide")

st.title("⚙️ Settings")

# Ensure user is logged in
if "username" not in st.session_state or not st.session_state.username:
    st.error("You must log in first.")
    st.stop()

username = st.session_state.username

# Load existing budget data
data = load_budget(username)
main_budget = data.get("main_budget") or 0
category_limits = json.loads(data.get("category_limits_json") or "{}")

st.subheader("💰 Main Monthly Budget")
main_val = st.number_input(
    "Set main budget (₹)",
    min_value=0.0,
    value=float(main_budget),
    step=500.0,
)

st.markdown("---")

st.subheader("📂 Category Limits")

CATEGORIES = [
    "Rent", "Groceries", "Food", "Transport", "Utilities",
    "Entertainment", "Healthcare", "Education", "Shopping", "Other"
]

new_limits = {}

# Render inputs for each category
for cat in CATEGORIES:
    new_limits[cat] = st.number_input(
        f"{cat} limit (₹)",
        min_value=0.0,
        step=100.0,
        value=float(category_limits.get(cat, 0)),
        key=f"limit_{cat}"
    )

st.markdown("---")

# Save settings
if st.button("💾 Save settings"):
    save_dict = {c: v for c, v in new_limits.items() if v > 0}

    set_budget(username, float(main_val), save_dict)

    st.success("Settings updated successfully!")

st.markdown("---")

st.info("Category budgets are used for alerts and dashboard warnings.")
