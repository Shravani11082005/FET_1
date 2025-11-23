import re
import json

# Optional ML classifier
try:
    import joblib
    TEXT_MODEL = joblib.load("trained_models/expense_category_model.pkl")
except Exception:
    TEXT_MODEL = None

# Regex for extracting amounts
AMOUNT_REGEX = re.compile(
    r"(?:₹|rs\.?|inr)?\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.\d{1,2})?|[0-9]+(?:\.\d{1,2})?)",
    re.IGNORECASE,
)

# Keyword-based mapping for category guess
KEYWORD_MAP = {
    r"rent": "Rent",
    r"grocer|supermarket|grocery|dmart|bigbasket|foodmart": "Groceries",
    r"fuel|petrol|diesel|uber|ola|taxi|bus|train": "Transport",
    r"electric|wifi|internet|bill": "Utilities",
    r"restaurant|cafe|dine|kfc|mcdonald": "Food",
    r"shoe|tshirt|clothes|shopping|ajio|zara|h&m": "Shopping",
    r"movie|netflix|spotify|ticket": "Entertainment",
    r"hospital|doctor|pharma|medical": "Healthcare",
    r"school|tuition|course|college|university": "Education",
}

# ---------------------------------------------------------
# Extract amount from OCR text
# ---------------------------------------------------------

def extract_amount_from_text(text: str):
    if not text:
        return None

    matches = AMOUNT_REGEX.findall(text)
    if not matches:
        return None

    values = []
    for m in matches:
        try:
            values.append(float(m.replace(",", "")))
        except:
            pass

    return max(values) if values else None


# ---------------------------------------------------------
# Guess category from OCR text
# ---------------------------------------------------------

def guess_category_from_text(text: str) -> str:
    if not text:
        return "Other"

    text_l = text.lower()

    # ML classifier (if available)
    if TEXT_MODEL:
        try:
            return str(TEXT_MODEL.predict([text_l])[0])
        except:
            pass

    # Keyword-based matching fallback
    for pattern, category in KEYWORD_MAP.items():
        if re.search(pattern, text_l):
            return category

    return "Other"
