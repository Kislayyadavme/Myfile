📩 Telegram Message Fetcher → Bot + GitHub Logger





A secure Telegram listener built with Telethon.
It automatically:

✅ Listens for private messages and Telegram OTP messages
✅ Prints messages beautifully in the console (with emojis)
✅ Forwards messages to your Telegram bot
✅ Logs everything to a GitHub repo file (messages.log)


---

✨ Features

🔑 OTP Detection → Captures Telegram login codes (sender = 777000)

💌 Private Messages → Logs all private chats

🤖 Bot Integration → Forwards messages to a chosen chat via your bot

📜 GitHub Sync → Updates a file (messages.log) in your repo automatically

🎨 Emoji-styled logs → Cleaner console output



---

⚙️ Installation

1. Clone the repo



git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

2. Install dependencies



pip install telethon requests

3. Configure your variables
Open message_fetcher.py and edit:



API_ID = "your_api_id"
API_HASH = "your_api_hash"
BOT_TOKEN = "your_bot_token"
ADMIN_CHAT_ID = "your_chat_id"

GITHUB_TOKEN = "your_github_pat"
REPO = "username/repo"
FILE_PATH = "messages.log"
BRANCH = "main"


---

▶️ Usage

Run the script:

python message_fetcher.py

📡 Output example:

🚀 Starting Telegram Client...
✅ Logged in as: Alice (123456789)
📡 Listening ONLY for private & OTP messages. Press Ctrl+C to stop.

🕒 2025-09-18 15:41:38
🔑 OTP MESSAGE from Telegram

Login code: 94406
---


---

📜 GitHub File Sync

Each captured message will be appended to messages.log in your repo automatically:

🕒 2025-09-18 15:41:38
💌 Private Message
👤 john_doe

Hello, how are you?
---


---

🔒 Security Notes

Keep your API ID, API HASH, Bot Token, and GitHub PAT secret.

If your PAT leaks → revoke it immediately from GitHub settings.

Do not share your session file (session_name.session).



---

🛠️ Built With

Python 3.8+

Telethon

GitHub REST API



---

⭐ Contributing

Pull requests are welcome! If you have feature ideas (like colored console logs or database storage), open an issue.


---

📄 License

MIT License © 2025


---
