import json, os, sys, requests

CFG_PATH = "app/instance/telegram_config.json"

def fail(msg):
    print("❌", msg)
    sys.exit(1)

# STEP 1 — Ensure config file exists
if not os.path.exists(CFG_PATH):
    fail(f"{CFG_PATH} does not exist. Create it first with your bot_token.")

cfg = json.load(open(CFG_PATH))
token = cfg.get("bot_token", "").strip()

if not token:
    fail("No bot_token found in telegram_config.json")

print("🔍 Validating bot token with Telegram getMe() ...")
r = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
data = r.json()

if not data.get("ok"):
    fail(f"Token invalid → {data}. Get a new token from BotFather.")

print("✅ Token valid! Bot username:", data["result"]["username"])
print()

print("📩 Fetching updates from Telegram ... (send /start to your bot before running)")
updates = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=10).json()

if not updates.get("ok"):
    fail(f"getUpdates failed → {updates}")

results = updates.get("result", [])

if not results:
    fail("No messages found. Open the bot and send /start, then run script again.")

# STEP 2 — Extract latest chat_id
chat_id = None
for upd in reversed(results):
    msg = upd.get("message") or upd.get("edited_message") or {}
    chat = msg.get("chat")
    if chat and chat.get("id"):
        chat_id = chat["id"]
        break

if not chat_id:
    fail("Could not detect chat_id. Send any message to bot and run again.")

print("📌 Detected chat_id:", chat_id)

# STEP 3 — Save chat_id to telegram_config.json
cfg["chat_id"] = chat_id
json.dump(cfg, open(CFG_PATH, "w"), indent=2)
print("💾 Saved chat_id to", CFG_PATH)

# STEP 4 — Test sendMessage
print("📨 Sending test message...")
test = requests.post(
    f"https://api.telegram.org/bot{token}/sendMessage",
    data={"chat_id": chat_id, "text": "FET: Telegram alerts are now working 🎉"},
    timeout=10
)

print("Telegram response:", test.status_code, test.text)

if test.json().get("ok"):
    print("✅ SUCCESS — You should see the message in Telegram now!")
else:
    print("⚠️ Message failed — check bot privacy settings or try again.")
