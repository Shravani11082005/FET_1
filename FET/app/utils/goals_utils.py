from .db import get_conn
import pandas as pd


# -------------------------------------
# Load all goals for a user
# -------------------------------------
def load_goals(username: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT goal_name, target_amount, months_to_complete, created_on
        FROM goals WHERE username = ?
    """, (username,))
    rows = cur.fetchall()
    conn.close()

    cols = ["goal_name", "target_amount", "months_to_complete", "created_on"]
    return pd.DataFrame(rows, columns=cols)


# -------------------------------------
# Add a new goal
# -------------------------------------
def add_goal(username: str, goal_name: str, target: float, months: int, created_on: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO goals (username, goal_name, target_amount, months_to_complete, created_on)
        VALUES (?, ?, ?, ?, ?)
    """, (username, goal_name, target, months, created_on))
    conn.commit()
    conn.close()


# -------------------------------------
# Delete a goal by name
# -------------------------------------
def delete_goal(username: str, goal_name: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM goals
        WHERE username = ? AND goal_name = ?
    """, (username, goal_name))
    conn.commit()
    conn.close()
