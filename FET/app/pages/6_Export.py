import streamlit as st
import pandas as pd
from utils.db import load_expenses

st.set_page_config(page_title="Export Data", page_icon="📤")

# -------------------------------------
# USER AUTH CHECK
# -------------------------------------
if "username" not in st.session_state:
    st.warning("Please log in first.")
    st.stop()

username = st.session_state["username"]

st.title("📤 Export Your Data")

# -------------------------------------
# LOAD EXPENSES
# -------------------------------------
exp = load_expenses(username)

# Normalize → Always DataFrame
if isinstance(exp, list):
    df = pd.DataFrame(exp) if exp else pd.DataFrame()
elif isinstance(exp, pd.DataFrame):
    df = exp
else:
    df = pd.DataFrame()  # fallback

# Ensure columns exist
expected_cols = ["date", "amount", "category", "assigned_member", "split_json", "note"]
for col in expected_cols:
    if col not in df.columns:
        df[col] = ""

# -------------------------------------
# SHOW TABLE
# -------------------------------------
if df.empty:
    st.info("No expenses to export yet.")
else:
    st.subheader("Your Expenses")
    st.dataframe(df, width='stretch')

    # -------------------------------------
    # EXPORT OPTIONS
    # -------------------------------------
    st.subheader("Download Options")

    # CSV export
    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇ Download CSV",
        data=csv_data,
        file_name=f"{username}_expenses.csv",
        mime="text/csv"
    )

    # Excel export
    xlsx_data = df.to_excel("temp.xlsx", index=False)
    with open("temp.xlsx", "rb") as f:
        st.download_button(
            label="⬇ Download Excel (.xlsx)",
            data=f,
            file_name=f"{username}_expenses.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

st.markdown("---")
st.caption("Export your expense data securely.")
