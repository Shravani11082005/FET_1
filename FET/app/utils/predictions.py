import numpy as np
import pandas as pd
from datetime import datetime
from .expenses import load_expenses


# ---------------------------------------------------------
# Predict next month spending
# ---------------------------------------------------------

def predict_next_month(username: str, months_back: int = 6):
    df = load_expenses(username)
    if df.empty:
        return None, [], []

    df["date_parsed"] = pd.to_datetime(df["date"], errors="coerce")
    df = df.dropna(subset=["date_parsed"])

    df["year_month"] = df["date_parsed"].dt.to_period("M")

    periods = sorted(df["year_month"].unique())
    recent = periods[-months_back:]

    amounts = []
    labels = []

    for p in recent:
        sel = df[df["year_month"] == p]
        amt = float(pd.to_numeric(sel["amount"], errors="coerce").fillna(0).sum())
        labels.append(str(p))
        amounts.append(amt)

    # Not enough data
    if len(amounts) < 2:
        return None, labels, amounts

    try:
        x = np.arange(len(amounts))
        y = np.array(amounts)
        coeffs = np.polyfit(x, y, 1)
        pred = float(np.poly1d(coeffs)(len(amounts)))
        return max(pred, 0), labels, amounts
    except:
        return None, labels, amounts
