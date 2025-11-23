import streamlit as st
from datetime import date
from app.utils.db import load_family, add_expense  # add_expense should exist in your utils.db

# Page config
st.set_page_config(page_title="Add Expense", page_icon="🧾")
st.title("🧾 Enter Expense Details")

# Require login
username = st.session_state.get("username")
if not username:
    st.warning("Please login to add expenses.")
    st.stop()

# ---------- Family members: robust extraction ----------
raw_fam = load_family(username)

# Normalize possible return types
fam_list = []
if raw_fam is None:
    fam_list = []
else:
    try:
        import pandas as _pd
        if isinstance(raw_fam, _pd.DataFrame):
            fam_list = raw_fam.to_dict(orient="records")
        else:
            fam_list = list(raw_fam)
    except Exception:
        try:
            fam_list = list(raw_fam)
        except Exception:
            fam_list = []

# Build members list
members = []
for row in fam_list:
    if row is None:
        continue
    if isinstance(row, dict):
        name = row.get("member_name") or row.get("member") or row.get("name")
        if name:
            members.append(str(name))
        continue

    try:
        if hasattr(row, "keys") and callable(row.keys):
            if "member_name" in row.keys():
                members.append(str(row["member_name"]))
                continue
    except Exception:
        pass

    if isinstance(row, (list, tuple)):
        if len(row) >= 2:
            members.append(str(row[1]))
            continue

    members.append(str(row))

# Remove duplicates
seen = set()
members_clean = []
for m in members:
    if m not in seen:
        seen.add(m)
        members_clean.append(m)
members = members_clean

# ---------- OCR (optional) ----------
OCR_AVAILABLE = False
try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

if OCR_AVAILABLE:
    st.markdown("**Upload receipt (optional)** — OCR will try to detect total amount.")
    up = st.file_uploader("Receipt image (png/jpg)", type=["png", "jpg", "jpeg"], key="ui_ocr_uploader")
    if up:
        try:
            img = Image.open(up)
            st.image(img, use_column_width=True)
            raw_text = pytesseract.image_to_string(img)
            st.text_area("OCR extracted text", value=raw_text, height=140)

            import re
            m = re.findall(r"(?:₹|Rs\.?|INR)?\s*([0-9]{1,3}(?:[,][0-9]{3})*(?:\.\d+)?|[0-9]+(?:\.\d+)?)", raw_text)
            detected_amt = 0.0
            if m:
                try:
                    nums = [float(x.replace(",","")) for x in m]
                    detected_amt = max(nums)
                except Exception:
                    detected_amt = 0.0

            st.session_state.ui_add_amount = float(detected_amt or 0.0)
            if detected_amt > 0:
                st.success(f"Detected amount: ₹{detected_amt:.2f}")

        except Exception:
            st.warning("OCR failed to process the image.")
else:
    st.info("OCR not available. Install pytesseract and Pillow to enable receipt scanning.")

st.markdown("---")

# ---------- Expense form ----------
with st.form("form_add_expense", clear_on_submit=False):
    amt_default = float(st.session_state.get("ui_add_amount", 0.0) or 0.0)
    amount = st.number_input("Amount (₹)", min_value=0.0, step=1.0, value=amt_default, format="%.2f", key="ui_amount_field_add")

    categories_list = ["Rent", "Groceries", "Food", "Transport", "Utilities", "Entertainment", "Healthcare", "Education", "Shopping", "Other"]
    cat_default = st.session_state.get("ui_add_category", "Other")
    if cat_default and cat_default not in categories_list:
        categories_list = [cat_default] + categories_list

    try:
        cat_index = categories_list.index(cat_default)
    except Exception:
        cat_index = 0

    category = st.selectbox("Category", options=categories_list, index=cat_index, key="ui_category_select_add")
    custom_cat = st.text_input("Or custom category (optional)", value="", key="ui_category_free_add")
    if custom_cat.strip():
        category = custom_cat.strip()

    assigned = ""
    if members:
        assigned = st.selectbox("Paid by (optional)", options=[""] + members, index=0, key="ui_assigned_add")
        if assigned == "":
            assigned = ""
    else:
        st.info("No family members found. Add members on the Family page first.")
        assigned = ""

    split_option = st.radio("Split option", options=["No split", "Split equally"], index=0, key="ui_split_opt_add")
    split_selected = []
    if split_option.startswith("Split") and members:
        split_selected = st.multiselect("Select members to split between", options=members, key="ui_split_members_add")
        if split_selected and amount:
            each = float(round(float(amount) / len(split_selected), 2))
            st.caption(f"Each: ₹{each:.2f}")

    note = st.text_input("Note (optional)", key="ui_note_add")

    submitted = st.form_submit_button("Save Expense", key="ui_btn_save_exp")

    if submitted:
        if amount is None or float(amount) <= 0:
            st.warning("Enter a valid amount.")
        else:
            split_dict = None
            if split_selected:
                try:
                    share = round(float(amount) / len(split_selected), 2)
                    split_dict = {m: float(share) for m in split_selected}
                except Exception:
                    split_dict = None

            try:
                ok = add_expense(
                    username=username,
                    amount=float(amount),
                    category=str(category),
                    assigned_member=str(assigned or ""),
                    split=split_dict,
                    note=str(note or "")
                )
            except TypeError:
                try:
                    from app.utils.db import append_expense
                    ok = append_expense(
                        username=username,
                        amount=float(amount),
                        category=str(category),
                        assigned_member=str(assigned or ""),
                        split=split_dict,
                        note=str(note or "")
                    )
                except Exception:
                    ok = False

            if ok:
                st.success("Expense added.")

                # -------------------------------------------------------------------
                # 🚨 Budget Exceeded Notification (Email + Telegram)
                # -------------------------------------------------------------------
                from app.utils.notify import notify_user
                from app.utils.db import get_user_budget, get_user_contacts, get_monthly_family_expenses
                
                try:
                    budget_limit = get_user_budget(username)
                    user_email, telegram_chat_id = get_user_contacts(username)
                    current_spend = get_monthly_family_expenses(username)

                    if budget_limit is not None and float(current_spend) > float(budget_limit):
                        subject = "Budget Exceeded — Family Expense Tracker"
                        text = (
                            f"Your monthly budget has been exceeded!\n\n"
                            f"Budget Limit: ₹{budget_limit}\n"
                            f"Current Spend: ₹{current_spend}\n"
                            f"Latest Expense: ₹{amount} ({category})"
                        )
                        html = (
                            f"<h3>🚨 Budget Exceeded!</h3>"
                            f"<p><b>Budget:</b> ₹{budget_limit}<br>"
                            f"<b>Current Spend:</b> ₹{current_spend}<br>"
                            f"<b>Latest Expense:</b> ₹{amount} ({category})</p>"
                        )

                        notify_user(
                            user_email=user_email,
                            telegram_chat_id=telegram_chat_id,
                            subject=subject,
                            message_text=text,
                            message_html=html
                        )

                except Exception as e:
                    st.warning("Could not send budget alert. Check logs.")
                # -------------------------------------------------------------------

                if "ui_add_amount" in st.session_state:
                    del st.session_state["ui_add_amount"]

                try:
                    st.session_state.pending_redirect = "Reports"
                    st.rerun()
                except Exception:
                    pass
            else:
                st.error("Failed to add expense. Check server logs or DB.")
