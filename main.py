import json
import logging
import os
import tempfile
from datetime import date
from pathlib import Path

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from analyzer import IntegratedAnalyzer
from config import BOT_TOKEN, MAX_FILE_SIZE, DAILY_LIMIT

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("bot")
usage = {}
SUPPORTED = {".py", ".js", ".ts", ".go", ".rs", ".java", ".txt"}


def allowed(user_id: int) -> bool:
    if DAILY_LIMIT <= 0:
        return True
    key = (user_id, date.today().isoformat())
    current = usage.get(key, 0)
    if current >= DAILY_LIMIT:
        return False
    usage[key] = current + 1
    return True


def format_report(name: str, result: dict) -> str:
    sec = result["security"]
    perf = result["performance"]
    style = result["style"]
    comp = result["complexity"]
    deps = result["dependencies"]
    return (
        f"📊 <b>Анализ: {name}</b>\n\n"
        f"🏆 Общая оценка: <b>{result['overall_grade']}</b>\n\n"
        f"🔐 <b>Безопасность</b>\n"
        f"• Оценка: {result['security_report']['security_score']}/100\n"
        f"• Проблем: {len(sec)}\n"
        f"• Критичных: {result['security_report']['critical']}\n"
        f"• Высоких: {result['security_report']['high']}\n\n"
        f"⚡ <b>Производительность</b>\n• Проблем: {len(perf)}\n\n"
        f"📐 <b>Сложность</b>\n• Cyclomatic: {comp['score']}\n• Уровень: {comp['level']}\n\n"
        f"🎨 <b>Стиль</b>\n• Оценка: {style['score']}/100\n• Проблем: {style['total_issues']}\n\n"
        f"📦 <b>Зависимости</b>\n• Стандартные: {deps['standard_library']}\n• Сторонние: {deps['third_party']}\n• Локальные: {deps['local']}"
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 <b>Code Analyzer Bot</b>\n\n"
        "Отправь файл с кодом — я выполню статический анализ.\n\n"
        "Поддержка: .py, .js, .ts, .go, .rs, .java, .txt\n\n"
        "/help — помощь",
        parse_mode="HTML",
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📚 <b>Как пользоваться</b>\n\n"
        "1. Прикрепи исходник как файл.\n"
        "2. Бот скачает его во временную папку.\n"
        "3. Код будет статически проанализирован.\n"
        "4. Получишь отчёт и JSON.\n\n"
        "⚠️ Загруженный код не запускается.",
        parse_mode="HTML",
    )


async def analyze_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if not message or not message.document:
        return
    if not allowed(update.effective_user.id):
        await message.reply_text("⛔ Лимит анализов на сегодня исчерпан.")
        return

    name = message.document.file_name or "code.txt"
    ext = Path(name).suffix.lower()
    if ext not in SUPPORTED:
        await message.reply_text("❌ Этот тип файла не поддерживается.")
        return
    if (message.document.file_size or 0) > MAX_FILE_SIZE:
        await message.reply_text(f"❌ Файл слишком большой. Максимум: {MAX_FILE_SIZE // 1024 // 1024} MB.")
        return

    status = await message.reply_text("🔍 Скачиваю и анализирую код…")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            temp_path = Path(tmp.name)
        tg_file = await message.document.get_file()
        await tg_file.download_to_drive(custom_path=str(temp_path))
        code = temp_path.read_text(encoding="utf-8", errors="replace")
        result = IntegratedAnalyzer(code, language=ext.lstrip(".")).run_full_analysis()
        await status.edit_text(format_report(name, result), parse_mode="HTML")

        json_path = temp_path.with_suffix(".json")
        json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        with json_path.open("rb") as f:
            await message.reply_document(document=f, caption="📄 Полный JSON-отчёт")
        json_path.unlink(missing_ok=True)
    except Exception:
        log.exception("Analysis failed")
        await status.edit_text("❌ Не удалось обработать файл. Проверь код и попробуй ещё раз.")
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)


def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN не задан. Укажи его в .env или config.py")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, analyze_document))
    log.info("Bot started")
    app.run_polling()


if __name__ == "__main__":
    main()
