import pandas as pd
from .db import get_connection

def load_family(username: str):
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT * FROM family WHERE username = ?",
        conn, params=[username]
    )
    return df

def save_family(username: str, rows: list):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("DELETE FROM family WHERE username = ?", (username,))

    for r in rows:
        cur.execute("""
            INSERT INTO family (username, member_name, relation, monthly_income, age, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username,
            r.get("member_name", ""),
            r.get("relation", ""),
            float(r.get("monthly_income", 0)),
            int(r.get("age", 0)),
            r.get("notes", "")
        ))

    conn.commit()
