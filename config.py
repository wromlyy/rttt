"""
⚙️ КОНФИГУРАЦИЯ ДЛЯ BOT ANALYZER
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ============= ГЛАВНЫЕ НАСТРОЙКИ =============

BOT_TOKEN = os.getenv("BOT_TOKEN")

ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", "8579582783").split(",") if x.strip()]

LOG_CHAT_ID = int(os.getenv("LOG_CHAT_ID", "-5356435006"))

# ============= ДИРЕКТОРИИ =============

BASE_DIR = Path(__file__).parent

TEMP_DIR = BASE_DIR / "temp_bots"
TEMP_DIR.mkdir(exist_ok=True)

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

ANALYZED_BOTS_DIR = BASE_DIR / "analyzed_bots_copies"
ANALYZED_BOTS_DIR.mkdir(exist_ok=True)

LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# ============= ЛОГИРОВАНИЕ =============

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = LOGS_DIR / "bot_analyzer.log"
LOG_FORMAT = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ============= ОГРАНИЧЕНИЯ =============

MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "10485760"))
MAX_ANALYSIS_TIME = int(os.getenv("MAX_ANALYSIS_TIME", "300"))
MAX_CONCURRENT_ANALYSIS = int(os.getenv("MAX_CONCURRENT_ANALYSIS", "5"))
DAILY_LIMIT_PER_USER = int(os.getenv("DAILY_LIMIT_PER_USER", "10"))

# ============= АНАЛИЗ =============

ENABLE_SECURITY_ANALYSIS = os.getenv("ENABLE_SECURITY_ANALYSIS", "true").lower() == "true"
ENABLE_PERFORMANCE_ANALYSIS = os.getenv("ENABLE_PERFORMANCE_ANALYSIS", "true").lower() == "true"
ENABLE_STYLE_ANALYSIS = os.getenv("ENABLE_STYLE_ANALYSIS", "true").lower() == "true"
ENABLE_COMPLEXITY_ANALYSIS = os.getenv("ENABLE_COMPLEXITY_ANALYSIS", "true").lower() == "true"
ENABLE_DEPENDENCY_ANALYSIS = os.getenv("ENABLE_DEPENDENCY_ANALYSIS", "true").lower() == "true"

# ============= ГЕНЕРАЦИЯ =============

ENABLE_CODE_GENERATION = os.getenv("ENABLE_CODE_GENERATION", "true").lower() == "true"
ENABLE_DOCUMENTATION = os.getenv("ENABLE_DOCUMENTATION", "true").lower() == "true"
ENABLE_JSON_EXPORT = os.getenv("ENABLE_JSON_EXPORT", "true").lower() == "true"
ENABLE_HTML_EXPORT = os.getenv("ENABLE_HTML_EXPORT", "true").lower() == "true"

# ============= TELEGRAM API =============

TELEGRAM_API_URL = "https://api.telegram.org"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

# ============= RATE LIMITING =============

RATE_LIMIT_SETTINGS = {
    "messages_per_second": int(os.getenv("RATE_LIMIT_MSG_SEC", "1")),
    "messages_per_minute": int(os.getenv("RATE_LIMIT_MSG_MIN", "30")),
    "messages_per_hour": int(os.getenv("RATE_LIMIT_MSG_HOUR", "500")),
}

# ============= КЕШИРОВАНИЕ =============

ENABLE_CACHE = os.getenv("ENABLE_CACHE", "true").lower() == "true"
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))
MAX_CACHE_SIZE = int(os.getenv("MAX_CACHE_SIZE", "100"))

# ============= УВЕДОМЛЕНИЯ =============

ENABLE_ERROR_NOTIFICATIONS = os.getenv("ENABLE_ERROR_NOTIFICATIONS", "true").lower() == "true"
ENABLE_PROGRESS_NOTIFICATIONS = os.getenv("ENABLE_PROGRESS_NOTIFICATIONS", "true").lower() == "true"

# ============= СТАТИСТИКА =============

ENABLE_STATISTICS = os.getenv("ENABLE_STATISTICS", "true").lower() == "true"
SAVE_STATISTICS_TO_DB = os.getenv("SAVE_STATISTICS_TO_DB", "false").lower() == "true"

def validate_config():
    errors = []
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        errors.append("BOT_TOKEN не установлен!")
    if not ADMIN_IDS:
        errors.append("ADMIN_IDS пустой список!")
    return errors

_errors = validate_config()
if _errors:
    import warnings
    for error in _errors:
        warnings.warn(f"Config warning: {error}", stacklevel=2)
