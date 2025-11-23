from .db import get_conn
import pandas as pd


# -------------------------------------
# Load family members for a user
# -------------------------------------
def load_family(username: str) -> pd.DataFrame:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT member_name, relation, monthly_income, age, notes, is_head
        FROM family WHERE username = ?
    """, (username,))
    rows = cur.fetchall()
    conn.close()

    cols = ["member_name", "relation", "monthly_income", "age", "notes", "is_head"]
    return pd.DataFrame(rows, columns=cols)


# -------------------------------------
# Total family monthly income
# -------------------------------------
def family_monthly_income(username: str) -> float:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT SUM(monthly_income) FROM family WHERE username = ?", (username,))
    amount = cur.fetchone()[0]
    conn.close()
    return amount if amount else 0.0
