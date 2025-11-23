import streamlit as st
from utils.db import (
    load_family,
    add_family_member,
    delete_family_member
)

st.set_page_config(page_title="Family Members", page_icon="👨‍👩‍👧‍👦")

st.title("👨‍👩‍👧 Family Members")

# -------------------------------------------------------------------
# 1️⃣ GET USER
# -------------------------------------------------------------------
username = st.session_state.get("username")
if not username:
    st.error("You must be logged in to access your family members.")
    st.stop()

# -------------------------------------------------------------------
# 2️⃣ LOAD FAMILY SAFELY
# -------------------------------------------------------------------
fam = load_family(username)
if fam is None:
    fam = []  # ensure list
elif not isinstance(fam, list):
    fam = []  # safety fallback

st.write("### Your Family Members")

# -------------------------------------------------------------------
# 3️⃣ SHOW EXISTING FAMILY MEMBERS
# -------------------------------------------------------------------
if len(fam) == 0:
    st.info("No family members added yet.")
else:
    for member in fam:
        # Convert tuple to dict if needed
        if isinstance(member, tuple):
            # (id, member_name, relation, monthly_income, age, notes, is_head, family_name)
            member = {
                "id": member[0],
                "member_name": member[1],
                "relation": member[2],
                "monthly_income": member[3],
                "age": member[4],
                "notes": member[5],
                "is_head": member[6],
                "family_name": member[7] if len(member) > 7 else ""
            }

        member_id = member.get("id")
        name = member.get("member_name", "Unknown")
        relation = member.get("relation", "")
        income = member.get("monthly_income", 0)
        age = member.get("age", 0)
        notes = member.get("notes", "")

        with st.expander(f"{name} — {relation}"):
            st.write(f"**Income:** ₹{income}")
            st.write(f"**Age:** {age}")
            st.write(f"**Notes:** {notes}")

            # Delete button for each member
            if st.button("🗑 Delete Member", key=f"del_{member_id}"):
                ok = delete_family_member(username, member_id)
                if ok:
                    st.success("Family member deleted successfully.")
                    st.rerun()
                else:
                    st.error("Failed to delete family member.")

# -------------------------------------------------------------------
# 4️⃣ ADD NEW FAMILY MEMBER
# -------------------------------------------------------------------
st.markdown("## ➕ Add New Member")

with st.form("add_family_member_form"):
    member_name = st.text_input("Member Name")
    relation = st.text_input("Relation (e.g., Father, Sister)")
    income = st.number_input("Monthly Income", min_value=0.0, step=100.0)
    age = st.number_input("Age", min_value=0)
    notes = st.text_area("Notes (optional)")
    is_head = st.checkbox("Is Family Head?")

    family_name = st.text_input("Family Name (same for all members, optional)", "")

    submitted = st.form_submit_button("Add Member")

    if submitted:
        if not member_name or not relation:
            st.warning("Member name and relation are required.")
        else:
            ok = add_family_member(
                username=username,
                member_name=member_name,
                relation=relation,
                monthly_income=income,
                age=age,
                notes=notes,
                is_head=is_head,
                family_name=family_name
            )
            if ok:
                st.success("Member added successfully!")
                st.rerun()
            else:
                st.error("Failed to add member.")
