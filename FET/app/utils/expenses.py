from .db import get_conn
import json
from datetime import datetime
import pandas as pd


# -------------------------------------
# Load all expenses for a user
# -------------------------------------
def load_expenses(username: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT date, amount, category, assigned_member, split_json, note FROM expenses WHERE username = ?", (username,))
    rows = cur.fetchall()
    conn.close()

    cols = ["date", "amount", "category", "assigned_member", "split_json", "note"]
    df = pd.DataFrame(rows, columns=cols)
    return df


# -------------------------------------
# Monthly summary (spent + saved)
# -------------------------------------
def monthly_summary(username: str, year: int, month: int, monthly_budget: float):
    df = load_expenses(username)
    if df.empty:
        return 0.0, monthly_budget

    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    sel = df[(df["date"].dt.year == year) & (df["date"].dt.month == month)]
    spent = float(sel["amount"].fillna(0).sum())

    saved = max(monthly_budget - spent, 0.0)
    return spent, saved


# -------------------------------------
# Yearly summary
# -------------------------------------
def yearly_summary(username: str, year: int, monthly_budget: float):
    df = load_expenses(username)
    if df.empty:
        return 0.0, monthly_budget * 12

    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    sel = df[df["date"].dt.year == year]
    spent = float(sel["amount"].fillna(0).sum())

    saved = max(monthly_budget * 12 - spent, 0.0)
    return spent, saved


# -------------------------------------
# Category breakdown for bar/pie charts
# -------------------------------------
def category_breakdown(username: str, year: int, month: int):
    df = load_expenses(username)
    if df.empty:
        return {}

    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    sel = df[(df["date"].dt.year == year) & (df["date"].dt.month == month)]

    if sel.empty:
        return {}

    return sel.groupby("category")["amount"].sum().sort_values(ascending=False).to_dict()
