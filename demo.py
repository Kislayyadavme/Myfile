"""
message_fetcher.py (Private + OTP messages → Bot + GitHub)

✨ Features:
 - Connects as your Telegram user (Telethon).
 - Listens only for:
     ✅ Private messages
     ✅ Telegram OTP messages
 - Prints them beautifully in console (with emojis).
 - Forwards them to your bot.
 - Updates/creates a file in your GitHub repo with logs.

📦 Requirements:
    pip install telethon requests
"""

import os
import base64
import asyncio
import requests
from telethon import TelegramClient, events

# ---------- TELEGRAM CONFIG ----------
API_ID = int(os.getenv("TG_API_ID", ""))
API_HASH = os.getenv("TG_API_HASH", "")
SESSION_NAME = os.getenv("TG_SESSION", "session_name")

BOT_TOKEN = os.getenv("ALERT_BOT_TOKEN", "YOUR_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "YOUR_CHAT_ID")

TELEGRAM_OFFICIAL = {777000}  # OTP sender ID

# ---------- GITHUB CONFIG ----------
# ⚠️ Replace these with your own details
GITHUB_TOKEN = "PUT-YOUR-TOKEN-HERE"   # <---- paste your token here
REPO = "your-username/your-repo"       # e.g. "kislayyadav/telegram-logger"
FILE_PATH = "messages.log"             # file path inside your repo
BRANCH = "main"                        # branch name

# ------------------------------------

client = TelegramClient(SESSION_NAME, API_ID, API_HASH)


def notify_via_bot(text: str):
    """Send message using bot API"""
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        print("🤖 [Bot Notify Disabled] ->", text)
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(url, data={"chat_id": ADMIN_CHAT_ID, "text": text})
        if resp.status_code != 200:
            print("⚠️ Bot notify failed:", resp.status_code, resp.text)
    except Exception as e:
        print("❌ Bot notify exception:", e)


def update_github_file(new_text: str):
    """Append logs to a file in GitHub repo using REST API"""
    url = f"https://api.github.com/repos/{REPO}/contents/{FILE_PATH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    # Get current file (to retrieve sha for update)
    r = requests.get(url, headers=headers, params={"ref": BRANCH})
    if r.status_code == 200:
        data = r.json()
        old_content = base64.b64decode(data["content"]).decode("utf-8")
        sha = data["sha"]
    else:
        old_content = ""
        sha = None

    # Append new text
    updated_content = old_content + "\n" + new_text
    b64_content = base64.b64encode(updated_content.encode("utf-8")).decode("utf-8")

    payload = {
        "message": "📜 Update log from Telegram script",
        "content": b64_content,
        "branch": BRANCH
    }
    if sha:
        payload["sha"] = sha

    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code not in (200, 201):
        print("⚠️ GitHub update failed:", resp.status_code, resp.text)
    else:
        print("✅ GitHub file updated successfully.")


@client.on(events.NewMessage(incoming=True))
async def handle_new_message(event):
    try:
        sender = await event.get_sender()
        sender_id = event.sender_id
        text = event.raw_text or ""

        # Only private chats and Telegram official
        if not event.is_private and sender_id not in TELEGRAM_OFFICIAL:
            return

        short_info = f"👤 {getattr(sender, 'username', None) or getattr(sender, 'first_name', None) or sender_id}"
        timestamp = event.message.date.strftime("%Y-%m-%d %H:%M:%S")

        # OTP vs normal private
        if sender_id in TELEGRAM_OFFICIAL:
            display = f"🕒 {timestamp}\n🔑 OTP MESSAGE from Telegram\n\n{text}\n---"
            forward_text = f"🔑 OTP received from Telegram Official\n🕒 {timestamp}\n\n{text}"
        else:
            display = f"🕒 {timestamp}\n💌 Private Message\n{short_info}\n\n{text}\n---"
            forward_text = f"💌 New private message\n{short_info}\n🕒 {timestamp}\n\n{text}"

        # Print
        print(display)

        # Forward via bot
        notify_via_bot(forward_text)

        # Append to GitHub file
        update_github_file(display)

    except Exception as exc:
        print("❌ Error handling new message:", exc)


async def main():
    print("🚀 Starting Telegram Client...")
    await client.start()
    me = await client.get_me()
    print(f"✅ Logged in as: {me.first_name} ({me.id})")
    print("📡 Listening ONLY for private & OTP messages. Press Ctrl+C to stop.")
    await client.run_until_disconnected()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("🛑 Stopped by user.")
