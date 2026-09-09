import os
from dotenv import load_dotenv

load_dotenv()

# Можно оставить токен в .env или задать прямо здесь вместо os.getenv(...)
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(5 * 1024 * 1024)))
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT", "30"))
