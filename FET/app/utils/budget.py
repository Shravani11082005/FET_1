# app/utils/budget.py

from app.utils.db import get_conn
import json

from .db import get_conn

from .db import get_conn

def load_budget(username: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT main_budget, category_limits_json
        FROM budgets
        WHERE username = ?
    """, (username,))

    row = cur.fetchone()
    conn.close()

    if not row:
        return {
            "main_budget": 0.0,
            "category_limits_json": "{}"
        }

    main_budget, cat_json = row
    return {
        "main_budget": float(main_budget or 0.0),
        "category_limits_json": cat_json or "{}"
    }


def get_category_limit(username: str, category: str) -> float:
    data = load_budget(username)
    try:
        limits = json.loads(data.get("category_limits_json", "{}"))
    except Exception:
        limits = {}
    return float(limits.get(category, 0.0) or 0.0)
