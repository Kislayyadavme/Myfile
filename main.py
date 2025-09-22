#!/usr/bin/env python3
"""
message_fetcher.py - Final stable build
Features:
 - Session creation via bot (phone -> OTP -> 2FA) with interactive admin input
 - Saves session locally at /data/user_session.session
 - Optionally pushes session, mode and logs to GitHub
 - Inline button UI: OTP / Private / All / Show
 - Admin commands: /getlog, /clearsession, /status
"""

import os
import base64
import asyncio
import requests
from typing import Optional
from telethon import TelegramClient, events, Button, errors
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

# ----------------- CONFIG -----------------
API_ID = int(os.getenv("API_ID"))                   # required
API_HASH = os.getenv("API_HASH", "")                   # required
BOT_TOKEN = os.getenv("BOT_TOKEN", "")                 # required
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID"))     # required numeric id

# GitHub optional (if you want file pushes)
GITHUB_TOKEN = os.getenv("GTOKEN")
REPO = os.getenv("REPO", "")       # e.g. "username/repo"
BRANCH = os.getenv("BRANCH", "main")

# Files and paths
LOCAL_DATA_DIR = "./data"
LOCAL_SESSION_PATH = os.path.join(LOCAL_DATA_DIR, "user_session.session")
LOCAL_MODE_PATH = os.path.join(LOCAL_DATA_DIR, "mode.txt")
LOCAL_LOG_PATH = os.path.join(LOCAL_DATA_DIR, "messages.log")

GITHUB_SESSION_PATH = "session.txt"
GITHUB_MODE_PATH = "mode.txt"
GITHUB_LOG_PATH = "messages.log"

# Defaults
TELEGRAM_OFFICIAL = {777000}   # set of official Telegram sender ids for OTP detection

# ----------------- VALIDATION -----------------
if not (API_ID and API_HASH and BOT_TOKEN and ADMIN_CHAT_ID):
    print("❗ Missing required environment variables. Please set API_ID, API_HASH, BOT_TOKEN and ADMIN_CHAT_ID.")
    # Do not exit here in case user runs locally for debugging; but warn.
# Ensure /data exists
os.makedirs(LOCAL_DATA_DIR, exist_ok=True)

# ----------------- GitHub helpers -----------------
def github_get_file(path: str) -> Optional[str]:
    """Fetch a file contents from GitHub repo (base64 decoded), or None."""
    if not (GITHUB_TOKEN and REPO):
        return None
    url = f"https://api.github.com/repos/{REPO}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers, params={"ref": BRANCH})
    if r.status_code == 200:
        data = r.json()
        return base64.b64decode(data["content"]).decode()
    return None

def github_put_file(path: str, content: str, message: str) -> bool:
    """Create or update a file in the GitHub repo. Returns True on success."""
    if not (GITHUB_TOKEN and REPO):
        return False
    url = f"https://api.github.com/repos/{REPO}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    b64 = base64.b64encode(content.encode()).decode()
    payload = {"message": message, "content": b64, "branch": BRANCH}
    # If file exists, get its sha
    r = requests.get(url, headers=headers, params={"ref": BRANCH})
    if r.status_code == 200:
        try:
            payload["sha"] = r.json()["sha"]
        except Exception:
            pass
    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code in (200, 201):
        return True
    else:
        print(f"⚠️ GitHub push failed ({resp.status_code}): {resp.text}")
        return False

# ----------------- local file helpers -----------------
def read_local(path: str) -> Optional[str]:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as e:
        print("Error reading local file:", e)
    return None

def write_local(path: str, content: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def append_local(path: str, content: str):
    with open(path, "a", encoding="utf-8") as f:
        f.write(content + "\n")

# ----------------- load mode -----------------
def load_mode() -> str:
    m = read_local(LOCAL_MODE_PATH)
    if m:
        return m.strip()
    # fallback to GitHub
    m = github_get_file(GITHUB_MODE_PATH)
    if m:
        write_local(LOCAL_MODE_PATH, m.strip())
        return m.strip()
    return "otp"

def save_mode(mode: str):
    write_local(LOCAL_MODE_PATH, mode)
    github_put_file(GITHUB_MODE_PATH, mode, f"🔄 Mode -> {mode}")

current_mode = load_mode()

# ----------------- Telegram clients (we'll start bot_client first) -----------------
bot_client = TelegramClient("bot_session", API_ID, API_HASH)
# user_client will be created later (when session known)
user_client: Optional[TelegramClient] = None

# ----------------- Helper: ask admin and wait for single reply -----------------
async def ask_admin_and_wait(prompt: str, timeout: int = 300) -> Optional[str]:
    """
    Send a prompt to the admin and wait for their next message reply.
    Returns the message text or None on timeout.
    """
    if not bot_client.is_connected():
        await bot_client.connect()

    await bot_client.send_message(ADMIN_CHAT_ID, f"❓ {prompt}")

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    async def _handler(event):
        # Only accept messages from the admin
        if event.sender_id == ADMIN_CHAT_ID and not future.done():
            future.set_result(event.raw_text.strip())
            # remove handler
            bot_client.remove_event_handler(_handler, events.NewMessage(from_users=ADMIN_CHAT_ID))

    # register the temporary handler
    bot_client.add_event_handler(_handler, events.NewMessage(from_users=ADMIN_CHAT_ID))

    try:
        return await asyncio.wait_for(future, timeout=timeout)
    except asyncio.TimeoutError:
        # cleanup handler if still there
        try:
            bot_client.remove_event_handler(_handler, events.NewMessage(from_users=ADMIN_CHAT_ID))
        except Exception:
            pass
        await bot_client.send_message(ADMIN_CHAT_ID, "⏳ Timeout waiting for your reply. Please /start again.")
        return None

# ----------------- Create session via bot inputs -----------------
async def create_and_save_session_via_bot() -> Optional[str]:
    """
    Use a temporary TelegramClient with StringSession to perform login using admin-provided
    phone + OTP + 2FA (if needed). Saves session string locally and pushes to GitHub (optional).
    """
    await bot_client.send_message(ADMIN_CHAT_ID, "🟢 Starting session creation. I will ask for phone -> OTP -> password (if needed).")

    phone = await ask_admin_and_wait("Please send your phone number (with country code, e.g. +1234567890):")
    if not phone:
        return None

    # Create temporary client with empty StringSession
    temp = TelegramClient(StringSession(), API_ID, API_HASH)
    await temp.connect()
    try:
        # send code request
        try:
            sent = await temp.send_code_request(phone)
        except Exception as e:
            await bot_client.send_message(ADMIN_CHAT_ID, f"❌ Failed to send code: {e}")
            await temp.disconnect()
            return None

        otp = await ask_admin_and_wait("Enter the OTP code you received (from Telegram):")
        if not otp:
            await temp.disconnect()
            return None

        try:
            # Try signing in
            # Telethon's sign_in handles code_hash internally using send_code_request result
            # but some versions might require code_hash; Telethon stores that in temp._sender...
            await temp.sign_in(phone=phone, code=otp)
        except SessionPasswordNeededError:
            pw = await ask_admin_and_wait("2FA detected. Enter your account password:")
            if not pw:
                await temp.disconnect()
                return None
            try:
                await temp.sign_in(password=pw)
            except Exception as e:
                await bot_client.send_message(ADMIN_CHAT_ID, f"❌ Password sign in failed: {e}")
                await temp.disconnect()
                return None
        except errors.PhoneCodeInvalidError:
            await bot_client.send_message(ADMIN_CHAT_ID, "❌ Invalid OTP. Please restart session creation.")
            await temp.disconnect()
            return None
        except Exception as e:
            # In some Telethon versions, sign_in(phone, code) may raise if it needs code_hash; fallback to sign_in with code_hash could be required.
            # We'll report the error to admin and abort gracefully.
            await bot_client.send_message(ADMIN_CHAT_ID, f"❌ Sign-in failed: {e}")
            await temp.disconnect()
            return None

        # At this point authorized
        session_str = temp.session.save()
        # Save locally to file
        write_local(LOCAL_SESSION_PATH, session_str)
        # Optionally push to GitHub
        if GITHUB_TOKEN and REPO:
            github_put_file(GITHUB_SESSION_PATH, session_str, "🔑 Add / update session")
        await bot_client.send_message(ADMIN_CHAT_ID, "✅ Session created and saved locally at `/data/user_session.session`.")
        await temp.disconnect()
        return session_str
    finally:
        if temp and temp.is_connected():
            await temp.disconnect()

# ----------------- Init user client (load session from local or GitHub or create) -----------------
async def init_user_client() -> Optional[TelegramClient]:
    global user_client
    # 1) try local
    session_str = read_local(LOCAL_SESSION_PATH)
    if not session_str:
        # try GitHub
        gh = github_get_file(GITHUB_SESSION_PATH)
        if gh:
            session_str = gh
            write_local(LOCAL_SESSION_PATH, session_str)

    if not session_str:
        # ask admin to create session
        session_str = await create_and_save_session_via_bot()
        if not session_str:
            await bot_client.send_message(ADMIN_CHAT_ID, "❌ Session creation aborted.")
            return None

    # create the client
    try:
        user_client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
        await user_client.connect()
        if not await user_client.is_user_authorized():
            await bot_client.send_message(ADMIN_CHAT_ID, "❌ Loaded session is not authorized. Removing local session and retrying.")
            # remove and try again
            try:
                os.remove(LOCAL_SESSION_PATH)
            except Exception:
                pass
            return await init_user_client()  # recursive try (will ask admin)
        return user_client
    except Exception as e:
        await bot_client.send_message(ADMIN_CHAT_ID, f"❌ Failed to start user client: {e}")
        return None

# ----------------- GitHub log update -----------------
def push_log_to_github(append_text: str):
    old = github_get_file(GITHUB_LOG_PATH) or ""
    new = (old + "\n" + append_text).lstrip("\n")
    github_put_file(GITHUB_LOG_PATH, new, "📜 Log update")

# ----------------- Bot UI & commands -----------------
@bot_client.on(events.NewMessage(pattern="/start"))
async def cmd_start(event):
    if event.sender_id != ADMIN_CHAT_ID:
        return
    await event.respond(
        "🤖 *Admin Control Panel*\nChoose a mode below (affects which messages are forwarded):",
        buttons=[
            [Button.inline("🔑 OTP Mode", b"otp"), Button.inline("💌 Private Mode", b"private")],
            [Button.inline("🌐 All Messages", b"all"), Button.inline("📋 Show Current Mode", b"show")],
            [Button.inline("🧾 Get Log", b"getlog"), Button.inline("🗑 Clear Session", b"clearsession")],
            [Button.inline("ℹ️ Status", b"status")]
        ],
        parse_mode="markdown"
    )

@bot_client.on(events.CallbackQuery)
async def cb_handler(event):
    global current_mode, user_client
    if event.sender_id != ADMIN_CHAT_ID:
        await event.answer("Unauthorized", alert=True)
        return

    data = event.data
    if data == b"otp":
        current_mode = "otp"; save_mode("otp")
        await event.edit("✅ Mode: 🔑 *OTP Only*", parse_mode="markdown")
    elif data == b"private":
        current_mode = "private"; save_mode("private")
        await event.edit("✅ Mode: 💌 *Private Chats Only*", parse_mode="markdown")
    elif data == b"all":
        current_mode = "all"; save_mode("all")
        await event.edit("✅ Mode: 🌐 *All Messages*", parse_mode="markdown")
    elif data == b"show":
        await event.answer(f"📋 Current mode: {current_mode.upper()}", alert=True)
    elif data == b"getlog":
        # try to fetch the last few lines of the local log, otherwise GitHub
        text = read_local(LOCAL_LOG_PATH) or github_get_file(GITHUB_LOG_PATH) or "No logs found."
        # send only last ~3000 chars to avoid flooding
        if len(text) > 3000:
            text = text[-3000:]
        await event.answer("📤 Sending log to you...", alert=True)
        await bot_client.send_message(ADMIN_CHAT_ID, f"🧾 Latest logs:\n\n{text}")
    elif data == b"clearsession":
        # remove local and GitHub session
        try:
            if os.path.exists(LOCAL_SESSION_PATH):
                os.remove(LOCAL_SESSION_PATH)
            if GITHUB_TOKEN and REPO:
                # Overwrite session file on GitHub with empty content (or delete via API - we overwrite)
                github_put_file(GITHUB_SESSION_PATH, "", "🗑 Clear session")
            # disconnect current user_client
            if user_client:
                try:
                    await user_client.disconnect()
                except Exception:
                    pass
                user_client = None
            await event.edit("🗑 Session cleared locally and on GitHub (if available). You can create a new session using `/start`.")
        except Exception as e:
            await event.answer(f"Error clearing session: {e}", alert=True)
    elif data == b"status":
        logged_in = "No"
        user_info = ""
        try:
            if user_client and await user_client.is_user_authorized():
                me = await user_client.get_me()
                logged_in = f"Yes — {me.first_name} ({me.id})"
                user_info = f"\nUser: {me.first_name} ({me.id})"
        except Exception:
            pass
        await event.answer(f"📡 Mode: {current_mode.upper()}\nLogged in: {logged_in}{user_info}", alert=True)

# Admin text commands too
@bot_client.on(events.NewMessage(pattern="/getlog"))
async def cmd_getlog(event):
    if event.sender_id != ADMIN_CHAT_ID: return
    text = read_local(LOCAL_LOG_PATH) or github_get_file(GITHUB_LOG_PATH) or "No logs found."
    if len(text) > 4000:
        text = text[-4000:]
    await event.reply(f"🧾 Latest logs:\n\n{text}")

@bot_client.on(events.NewMessage(pattern="/clearsession"))
async def cmd_clearsession(event):
    if event.sender_id != ADMIN_CHAT_ID: return
    try:
        if os.path.exists(LOCAL_SESSION_PATH):
            os.remove(LOCAL_SESSION_PATH)
        if GITHUB_TOKEN and REPO:
            github_put_file(GITHUB_SESSION_PATH, "", "🗑 Clear session")
        global user_client
        if user_client:
            try:
                await user_client.disconnect()
            except Exception:
                pass
            user_client = None
        await event.reply("🗑 Session cleared.")
    except Exception as e:
        await event.reply(f"Error: {e}")

@bot_client.on(events.NewMessage(pattern="/status"))
async def cmd_status(event):
    if event.sender_id != ADMIN_CHAT_ID: return
    logged = "No"
    uinfo = ""
    try:
        if user_client and await user_client.is_user_authorized():
            me = await user_client.get_me()
            logged = f"Yes — {me.first_name} ({me.id})"
            uinfo = f"\nUser: {me.first_name} ({me.id})"
    except Exception:
        pass
    await event.reply(f"📡 Mode: {current_mode.upper()}\nLogged in: {logged}{uinfo}")

# ----------------- Register user message handler once user_client is ready -----------------
def register_user_handlers(uclient: TelegramClient):
    @uclient.on(events.NewMessage(incoming=True))
    async def user_message_handler(event):
        try:
            sender = await event.get_sender()
            sender_id = event.sender_id
            text = event.raw_text or ""
            chat_id = getattr(event.peer_id, "channel_id", None) or getattr(event.peer_id, "user_id", None) or getattr(event, "chat_id", None)
            # Filtering based on mode
            if current_mode == "otp" and sender_id not in TELEGRAM_OFFICIAL:
                return
            if current_mode == "private" and not event.is_private:
                return

            name = getattr(sender, "username", None) or getattr(sender, "first_name", None) or "Unknown"
            timestamp = event.message.date.strftime("%Y-%m-%d %H:%M:%S")
            header = f"🕒 {timestamp} | From: {name} (id:{sender_id}) | chat:{chat_id}"
            body = text
            display = f"{header}\n\n{body}\n---"
            print(display)

            # send to admin
            try:
                await bot_client.send_message(ADMIN_CHAT_ID, display)
            except Exception as e:
                print("Failed to forward to admin:", e)

            # append local log and push to GitHub
            append_local(LOCAL_LOG_PATH, display)
            if GITHUB_TOKEN and REPO:
                try:
                    push_log_to_github(display)
                except Exception as e:
                    print("Failed to push log to GitHub:", e)

        except Exception as exc:
            print("Error in handling incoming message:", exc)

# ----------------- Run main -----------------
async def main():
    print("🚀 Starting bot client...")
    await bot_client.start(bot_token=BOT_TOKEN)
    print("✅ Bot client started.")

    # Initialize user client (may create session via admin flow)
    uclient = await init_user_client()
    if not uclient:
        await bot_client.send_message(ADMIN_CHAT_ID, "❌ Could not initialize user client. Exiting.")
        # keep bot running so admin can try /clearsession or recreate session
        return

    # Register handlers for user client
    register_user_handlers(uclient)

    # Announce status to admin
    try:
        me = await uclient.get_me()
        await bot_client.send_message(ADMIN_CHAT_ID, f"✅ Logged in as {me.first_name} ({me.id})\n📡 Mode: {current_mode.upper()}")
    except Exception:
        await bot_client.send_message(ADMIN_CHAT_ID, f"✅ User client started. 📡 Mode: {current_mode.upper()}")

    # Keep both clients running concurrently
    await asyncio.gather(
        uclient.run_until_disconnected(),
        bot_client.run_until_disconnected()
    )

if __name__ == "__main__":
    try:
        # Run main loop
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        print("🛑 Shutting down by user")
    except Exception as e:
        print("Fatal error in main:", e)
