import pandas as pd
from datetime import datetime
from .expenses import load_expenses

def category_breakdown(username: str, year: int, month: int):
    df = load_expenses(username)
    if df.empty:
        return pd.DataFrame(columns=["category", "amount"])

    df["date"] = pd.to_datetime(df["date"])
    mdf = df[(df["date"].dt.year == year) & (df["date"].dt.month == month)]

    return mdf.groupby("category")["amount"].sum().reset_index()
