import pandas as pd
from datetime import datetime
from .db import get_connection

def load_goals(username: str):
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT * FROM goals WHERE username = ?",
        conn, params=[username]
    )
    return df

def add_goal(username: str, name: str, target: float, months: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO goals (username, goal_name, target_amount, months_to_complete, created_on) VALUES (?, ?, ?, ?, ?)",
        (username, name, target, months, datetime.now().strftime("%Y-%m-%d"))
    )
    conn.commit()
