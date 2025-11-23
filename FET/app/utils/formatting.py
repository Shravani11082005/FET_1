# utils/formatting.py

from datetime import datetime

# ---------------------------------------------------------
# Format a number into Rupees
# ---------------------------------------------------------

def rupee(value) -> str:
    """
    Format a float or numeric value into ₹ x,xxx.xx format.
    """
    try:
        return f"₹ {float(value):,.2f}"
    except Exception:
        return "₹ 0.00"


# ---------------------------------------------------------
# Format yyyy-mm-dd → 12 Jan 2025
# ---------------------------------------------------------

def format_date(d):
    """
    Accepts a date string or datetime, returns readable date.
    """
    if d is None:
        return ""

    try:
        if isinstance(d, str):
            dt = datetime.fromisoformat(d)
        else:
            dt = d
        return dt.strftime("%d %b %Y")
    except:
        return str(d)
