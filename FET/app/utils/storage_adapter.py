# utils/storage_adapter.py
# Provides a few functions matching the previous storage API but using the new DB module.

from . import db

def ensure_structure():
    # db.init_db already called on import; noop here
    return

# CSV-like API
def load_csv(name):
    if name == "users":
        # return list of dicts
        rows = db.get_conn()  # not used directly; prefer db functions below
        # but for pages using the old load_csv, better to use DB-specific helpers
        raise RuntimeError("Please migrate code to use db.* functions or use provided helpers.")
    raise RuntimeError("Adapter: unsupported operation. Use db.* functions instead.")

# Direct db wrappers (recommended)
add_user = db.add_user
check_login = db.check_login
get_user_email = db.get_user_email

add_expense = db.add_expense
load_expenses = db.load_expenses

save_family = db.save_family
load_family = db.load_family

add_goal = db.add_goal
load_goals = db.load_goals
delete_goal = db.delete_goal

save_budget = db.save_budget
load_budget = db.load_budget

# telegram / notifications
save_notification_config = db.save_notification_config
load_notification_config = db.load_notification_config
save_telegram_config_row = db.save_telegram_config_row
load_telegram_config_row = db.load_telegram_config_row
