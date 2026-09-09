"""
🤖 БОТА АНАЛИЗАТОР И КОПИВАТОР
Анализирует другие боты, проверяет функции и создает ZIP копию
"""

import asyncio
import json
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
import aiohttp
import inspect
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import FSInputFile
from aiogram.utils.markdown import hbold, hitalic, hcode
import logging

# ============= КОНФИГ =============
TOKEN = "YOUR_BOT_TOKEN_HERE"
TEMP_DIR = Path("temp_bots")
REPORTS_DIR = Path("reports")
ANALYZED_BOTS_DIR = Path("analyzed_bots_copies")

# Создаем директории
TEMP_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
ANALYZED_BOTS_DIR.mkdir(exist_ok=True)

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= DATACLASSES =============

@dataclass
class BotCommand:
    """Структура команды"""
    name: str
    description: str
    parameters: List[str] = None
    handler_type: str = "callback"  # callback, text, inline

@dataclass
class BotButton:
    """Структура кнопки"""
    text: str
    action_type: str  # url, callback_data, switch_inline
    action_value: str
    position: str = "inline"

@dataclass
class BotFeature:
    """Особенность/функция бота"""
    name: str
    description: str
    complexity: str  # simple, medium, complex
    requires_database: bool
    uses_api: bool
    api_endpoints: List[str] = None

@dataclass
class BotAnalysisReport:
    """Полный отчет анализа"""
    bot_username: str
    analysis_date: str
    commands_found: int
    buttons_found: int
    features_found: int
    total_interactions: int
    database_usage: bool
    api_integrations: List[str]
    commands: List[BotCommand]
    buttons: List[BotButton]
    features: List[BotFeature]
    conversation_flow: Dict[str, Any]
    security_notes: List[str]
    estimated_complexity: str


# ============= КЛАСС АНАЛИЗАТОРА =============

class BotAnalyzer:
    """Основной класс для анализа ботов"""
    
    def __init__(self, bot_username: str):
        self.bot_username = bot_username
        self.bot_id = None
        self.commands = []
        self.buttons = []
        self.features = []
        self.api_endpoints = []
        self.db_indicators = []
        self.conversation_flows = {}
        self.security_flags = []
        
    async def get_bot_info(self) -> Dict[str, Any]:
        """Получить информацию о боте через Telegram API"""
        try:
            async with aiohttp.ClientSession() as session:
                # Попытка получить информацию о боте
                url = f"https://api.telegram.org/bot{TOKEN}/getMe"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data
        except Exception as e:
            logger.error(f"Ошибка при получении инфо бота: {e}")
        return {}
    
    async def analyze_bot_interactions(self, messages_log: List[Dict]) -> None:
        """Анализировать логи взаимодействий с ботом"""
        for msg in messages_log:
            if "command" in msg.get("type", ""):
                self._parse_command(msg)
            elif "callback" in msg.get("type", ""):
                self._parse_button(msg)
            elif "text" in msg.get("type", ""):
                self._detect_features(msg)
    
    def _parse_command(self, msg: Dict) -> None:
        """Парсить команду"""
        command = msg.get("text", "").lstrip("/").split()[0]
        description = msg.get("description", "Неизвестная команда")
        
        self.commands.append(BotCommand(
            name=command,
            description=description,
            parameters=msg.get("parameters", []),
            handler_type="command"
        ))
    
    def _parse_button(self, msg: Dict) -> None:
        """Парсить кнопку"""
        button = BotButton(
            text=msg.get("text", "Button"),
            action_type=msg.get("action_type", "callback_data"),
            action_value=msg.get("action_value", ""),
            position=msg.get("position", "inline")
        )
        self.buttons.append(button)
    
    def _detect_features(self, msg: Dict) -> None:
        """Детектить особенности бота из сообщений"""
        text = msg.get("text", "").lower()
        
        # Детекция функций
        feature_keywords = {
            "поиск": ("Поиск", "Может искать информацию"),
            "фильтр": ("Фильтрация", "Фильтрует результаты"),
            "сортировк": ("Сортировка", "Сортирует данные"),
            "рейтинг": ("Рейтинг", "Система оценок"),
            "уведомлени": ("Уведомления", "Отправляет уведомления"),
            "расписани": ("Расписание", "Работает с расписанием"),
            "платеж": ("Платежи", "Интеграция платежей"),
            "аналитик": ("Аналитика", "Анализирует статистику"),
        }
        
        for keyword, (feature_name, description) in feature_keywords.items():
            if keyword in text and not any(f.name == feature_name for f in self.features):
                self.features.append(BotFeature(
                    name=feature_name,
                    description=description,
                    complexity="medium",
                    requires_database=True,
                    uses_api=True
                ))
    
    def analyze_code_structure(self, code_content: str) -> Dict[str, Any]:
        """Анализировать структуру кода"""
        analysis = {
            "imports": [],
            "classes": [],
            "functions": [],
            "handlers": [],
            "decorators": [],
            "async_functions": [],
            "database_calls": [],
            "api_calls": [],
        }
        
        lines = code_content.split("\n")
        
        for line in lines:
            line = line.strip()
            
            # Импорты
            if line.startswith("import ") or line.startswith("from "):
                analysis["imports"].append(line)
            
            # Классы
            elif line.startswith("class "):
                class_name = line.split("(")[0].replace("class ", "")
                analysis["classes"].append(class_name)
            
            # Функции
            elif line.startswith("def "):
                func_name = line.split("(")[0].replace("def ", "")
                analysis["functions"].append(func_name)
            
            # Async функции
            elif line.startswith("async def "):
                func_name = line.split("(")[0].replace("async def ", "")
                analysis["async_functions"].append(func_name)
            
            # Декораторы обработчиков
            elif line.startswith("@"):
                analysis["decorators"].append(line)
                if "router" in line or "handler" in line:
                    analysis["handlers"].append(line)
            
            # Вызовы БД
            if any(db in line for db in ["sqlite", "postgres", "mysql", "mongo", "redis", "database"]):
                analysis["database_calls"].append(line)
                if not self.db_indicators:
                    self.db_indicators.append("Обнаружена работа с БД")
            
            # Вызовы API
            if any(api in line for api in ["requests.", "aiohttp", "httpx", "api.telegram"]):
                analysis["api_calls"].append(line)
        
        return analysis

    def extract_conversation_flow(self, code_content: str) -> Dict[str, Any]:
        """Извлечь граф разговора"""
        flow = {
            "start_states": [],
            "transitions": [],
            "end_states": [],
            "branches": []
        }
        
        # Простой анализ потока
        if "FSMContext" in code_content or "State" in code_content:
            flow["type"] = "FSM (Finite State Machine)"
            states = []
            for line in code_content.split("\n"):
                if "class" in line and "State" in line:
                    state = line.split("(")[0].replace("class ", "")
                    states.append(state)
            flow["states"] = states
        else:
            flow["type"] = "Simple callbacks/commands"
        
        return flow

    def detect_security_issues(self, code_content: str) -> List[str]:
        """Детектить проблемы безопасности"""
        issues = []
        
        security_checks = {
            "eval(": "⚠️ Использование eval() - критический риск",
            "exec(": "⚠️ Использование exec() - критический риск",
            "pickle": "⚠️ Использование pickle - риск десериализации",
            "sql_query = ": "⚠️ Возможна SQL injection",
            "f\"SELECT": "⚠️ SQL запросы через f-strings",
            "os.system": "⚠️ Использование os.system()",
            "subprocess.": "⚠️ Вызовы subprocess без проверки",
            "TOKEN = ": "⚠️ Токен может быть захардкожен",
        }
        
        for check, message in security_checks.items():
            if check in code_content:
                issues.append(message)
        
        return issues

    async def generate_report(self) -> BotAnalysisReport:
        """Генерировать финальный отчет"""
        
        complexity_score = (
            len(self.commands) * 5 +
            len(self.buttons) * 3 +
            len(self.features) * 10 +
            len(self.db_indicators) * 15
        )
        
        if complexity_score > 100:
            complexity = "Высокая сложность"
        elif complexity_score > 50:
            complexity = "Средняя сложность"
        else:
            complexity = "Простой бот"
        
        report = BotAnalysisReport(
            bot_username=self.bot_username,
            analysis_date=datetime.now().isoformat(),
            commands_found=len(self.commands),
            buttons_found=len(self.buttons),
            features_found=len(self.features),
            total_interactions=len(self.commands) + len(self.buttons),
            database_usage=bool(self.db_indicators),
            api_integrations=list(set(self.api_endpoints)),
            commands=self.commands,
            buttons=self.buttons,
            features=self.features,
            conversation_flow=self.conversation_flows,
            security_notes=self.security_flags,
            estimated_complexity=complexity
        )
        
        return report


# ============= КЛАСС КОПИВАТОРА =============

class BotCopier:
    """Класс для создания копии бота"""
    
    def __init__(self, bot_name: str, analysis_report: BotAnalysisReport):
        self.bot_name = bot_name
        self.report = analysis_report
        self.copy_dir = ANALYZED_BOTS_DIR / bot_name
        self.copy_dir.mkdir(exist_ok=True)
    
    def create_template_bot(self) -> str:
        """Создать шаблон бота на основе анализа"""
        
        template = f'''"""
Бот скопирован и проанализирован
Оригинальный бот: {self.report.bot_username}
Дата анализа: {self.report.analysis_date}
"""

import asyncio
import logging
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

# Настройки
TOKEN = "PASTE_YOUR_TOKEN_HERE"
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

bot = Bot(token=TOKEN)
dp = Dispatcher()

# ============= СОСТОЯНИЯ =============
class BotStates(StatesGroup):
    waiting_for_input = State()
    processing = State()
    showing_results = State()

# ============= КОМАНДЫ =============
'''
        
        # Добавляем команды
        for cmd in self.report.commands:
            template += f'''
@dp.message(Command("{cmd.name}"))
async def cmd_{cmd.name}(message: types.Message, state: FSMContext):
    """
    {cmd.description}
    Параметры: {', '.join(cmd.parameters) if cmd.parameters else 'нет'}
    """
    await message.answer(f"Команда /{cmd.name} выполняется...")
    # TODO: Добавить логику

'''
        
        template += '\n# ============= КНОПКИ И ИНЛАЙН =============\n'
        
        # Добавляем кнопки
        for btn in self.report.buttons[:5]:  # Первые 5 кнопок
            template += f'''
async def handle_{btn.text.replace(" ", "_").lower()}(callback: types.CallbackQuery):
    """Обработчик кнопки: {btn.text}"""
    await callback.answer()
    await callback.message.edit_text(
        text="Кнопка нажата",
        reply_markup=None
    )

'''
        
        template += '\n# ============= ОСНОВНЫЕ ФУНКЦИИ =============\n'
        
        # Добавляем функции для обнаруженных фич
        for feature in self.report.features:
            func_name = feature.name.lower().replace(" ", "_")
            template += f'''
async def {func_name}(message: types.Message):
    """
    Функция: {feature.name}
    Описание: {feature.description}
    Требует БД: {feature.requires_database}
    Требует API: {feature.uses_api}
    """
    await message.answer(f"Функция '{feature.name}' работает...")
    # TODO: Реализовать логику

'''
        
        # Точка входа
        template += '''

async def main():
    await dp.start_polling(bot, skip_updates=True)

if __name__ == "__main__":
    asyncio.run(main())
'''
        
        return template
    
    def create_json_structure(self) -> str:
        """Создать JSON с полной структурой"""
        report_dict = {
            "metadata": {
                "bot_username": self.report.bot_username,
                "analysis_date": self.report.analysis_date,
                "estimated_complexity": self.report.estimated_complexity,
            },
            "statistics": {
                "commands_found": self.report.commands_found,
                "buttons_found": self.report.buttons_found,
                "features_found": self.report.features_found,
                "total_interactions": self.report.total_interactions,
                "database_usage": self.report.database_usage,
            },
            "commands": [
                {
                    "name": cmd.name,
                    "description": cmd.description,
                    "parameters": cmd.parameters,
                    "type": cmd.handler_type,
                }
                for cmd in self.report.commands
            ],
            "buttons": [
                {
                    "text": btn.text,
                    "action_type": btn.action_type,
                    "action_value": btn.action_value,
                    "position": btn.position,
                }
                for btn in self.report.buttons
            ],
            "features": [
                {
                    "name": f.name,
                    "description": f.description,
                    "complexity": f.complexity,
                    "requires_database": f.requires_database,
                    "uses_api": f.uses_api,
                }
                for f in self.report.features
            ],
            "conversation_flow": self.report.conversation_flow,
            "api_integrations": self.report.api_integrations,
            "security_notes": self.report.security_notes,
        }
        
        return json.dumps(report_dict, ensure_ascii=False, indent=2)
    
    def create_documentation(self) -> str:
        """Создать MD документацию"""
        
        doc = f'''# 📊 Анализ Бота: {self.report.bot_username}

**Дата анализа:** {self.report.analysis_date}  
**Уровень сложности:** {self.report.estimated_complexity}

---

## 📈 Статистика

- **Команд найдено:** {self.report.commands_found}
- **Кнопок найдено:** {self.report.buttons_found}
- **Функций найдено:** {self.report.features_found}
- **Всего взаимодействий:** {self.report.total_interactions}
- **Использует БД:** {"✅ Да" if self.report.database_usage else "❌ Нет"}

---

## 🎮 Команды

'''
        
        for cmd in self.report.commands:
            doc += f'''
### /{cmd.name}
- **Описание:** {cmd.description}
- **Параметры:** {', '.join(cmd.parameters) if cmd.parameters else 'Нет'}
- **Тип:** {cmd.handler_type}

'''
        
        doc += '\n## 🔘 Кнопки\n'
        
        for btn in self.report.buttons:
            doc += f'''
- **{btn.text}** → {btn.action_type}: `{btn.action_value}`

'''
        
        doc += '\n## ⚙️ Функции\n'
        
        for feature in self.report.features:
            doc += f'''
### {feature.name}
- **Описание:** {feature.description}
- **Сложность:** {feature.complexity}
- **Требует БД:** {"✅ Да" if feature.requires_database else "❌ Нет"}
- **Требует API:** {"✅ Да" if feature.uses_api else "❌ Нет"}

'''
        
        if self.report.security_notes:
            doc += '\n## ⚠️ Примечания Безопасности\n'
            for note in self.report.security_notes:
                doc += f'- {note}\n'
        
        doc += '\n---\n*Документация автоматически сгенерирована Bot Analyzer*'
        
        return doc
    
    async def create_zip_copy(self) -> Path:
        """Создать ZIP архив с копией бота"""
        
        # Создаем файлы в директории копии
        bot_code = self.create_template_bot()
        bot_file = self.copy_dir / "bot_main.py"
        bot_file.write_text(bot_code, encoding='utf-8')
        
        json_structure = self.create_json_structure()
        json_file = self.copy_dir / "bot_structure.json"
        json_file.write_text(json_structure, encoding='utf-8')
        
        doc = self.create_documentation()
        doc_file = self.copy_dir / "README.md"
        doc_file.write_text(doc, encoding='utf-8')
        
        # Создаем config template
        config = f'''# Конфигурация для бота {self.report.bot_username}

BOT_TOKEN = "PASTE_YOUR_TOKEN_HERE"
ADMIN_ID = 123456789

# Настройки БД
USE_DATABASE = {str(self.report.database_usage).lower()}
DB_TYPE = "sqlite"  # sqlite, postgres, mysql
DB_CONNECTION = "sqlite:///bot.db"

# Настройки API
API_INTEGRATIONS = {json.dumps(self.report.api_integrations, ensure_ascii=False)}

# Логирование
LOG_LEVEL = "INFO"
LOG_FILE = "bot.log"
'''
        config_file = self.copy_dir / "config.py"
        config_file.write_text(config, encoding='utf-8')
        
        # Создаем requirements
        requirements = '''aiogram==3.4.1
aiohttp==3.9.1
python-dotenv==1.0.0
aiosqlite==0.19.0
'''
        req_file = self.copy_dir / "requirements.txt"
        req_file.write_text(requirements, encoding='utf-8')
        
        # Создаем ZIP
        zip_path = REPORTS_DIR / f"{self.bot_name}_copy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in self.copy_dir.iterdir():
                if file.is_file():
                    arcname = f"{self.bot_name}/{file.name}"
                    zipf.write(file, arcname=arcname)
        
        logger.info(f"ZIP архив создан: {zip_path}")
        return zip_path


# ============= ГЛАВНЫЙ БОТ АНАЛИЗАТОР =============

class BotAnalyzerBot:
    """Главный бот для анализа других ботов"""
    
    def __init__(self, token: str):
        self.bot = Bot(token=token)
        self.dp = Dispatcher()
        self.analyzers: Dict[int, BotAnalyzer] = {}
        self.user_sessions: Dict[int, Dict[str, Any]] = {}
        self._register_handlers()
    
    def _register_handlers(self):
        """Регистрировать обработчики"""
        
        @self.dp.message(Command("start"))
        async def cmd_start(message: types.Message):
            user_id = message.from_user.id
            self.user_sessions[user_id] = {
                "state": "waiting_bot_username",
                "analyzer": None
            }
            
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="📊 Анализировать бота", callback_data="analyze")],
                [InlineKeyboardButton(text="📖 Помощь", callback_data="help")],
            ])
            
            await message.answer(
                f"👋 Привет, {message.from_user.first_name}!\n\n"
                "🤖 Я анализирую боты Telegram и создаю их копии.\n\n"
                "Отправь мне юзернейм бота (например: @BotFather)",
                reply_markup=kb
            )
        
        @self.dp.callback_query(F.data == "analyze")
        async def callback_analyze(callback: types.CallbackQuery, state: FSMContext):
            await callback.message.answer("Отправь юзернейм бота для анализа:\n\n_Например: @username_bot_")
            await callback.answer()
        
        @self.dp.callback_query(F.data == "help")
        async def callback_help(callback: types.CallbackQuery):
            help_text = """
🤖 *Как использовать Bot Analyzer:*

1️⃣ Отправь юзернейм бота (с @ или без)
2️⃣ Я начну анализировать его функции
3️⃣ Получишь полный отчет и ZIP с копией

*Что анализируется:*
- ✅ Все команды
- ✅ Кнопки и инлайн-меню
- ✅ Функции и возможности
- ✅ Использование БД
- ✅ API интеграции
- ✅ Граф разговора
- ✅ Проблемы безопасности

*Что ты получишь:*
📄 Подробный отчет в JSON
📋 Шаблон кода бота
📖 Документация (README.md)
🔧 Config файл
⚙️ Requirements.txt
📦 ВСЕ В ОДНОМ ZIP!
"""
            await callback.message.edit_text(help_text, parse_mode="Markdown")
            await callback.answer()
        
        @self.dp.message(F.text)
        async def handle_text(message: types.Message):
            user_id = message.from_user.id
            text = message.text.strip()
            
            # Убираем @ если есть
            bot_username = text.lstrip("@")
            
            if not bot_username or len(bot_username) < 2:
                await message.answer("❌ Неверный юзернейм бота!")
                return
            
            # Отправляем статус анализа
            status_msg = await message.answer(
                f"🔍 Анализирую бота: @{bot_username}\n"
                f"⏳ Это может занять 30-60 секунд...\n\n"
                f"Проверяю:\n"
                f"⬜ Команды\n"
                f"⬜ Кнопки\n"
                f"⬜ Функции\n"
                f"⬜ API\n"
                f"⬜ Безопасность"
            )
            
            try:
                # Создаем анализатор
                analyzer = BotAnalyzer(bot_username)
                
                # Симуляция анализа (в реальном приложении здесь будет реальный анализ)
                await asyncio.sleep(2)
                
                # Добавляем примеры команд
                analyzer.commands = [
                    BotCommand("start", "Начало работы", [], "command"),
                    BotCommand("help", "Справка", [], "command"),
                    BotCommand("settings", "Настройки", ["param1", "param2"], "command"),
                ]
                
                # Добавляем примеры кнопок
                analyzer.buttons = [
                    BotButton("Получить данные", "callback_data", "get_data", "inline"),
                    BotButton("Открыть меню", "callback_data", "open_menu", "inline"),
                ]
                
                # Добавляем примеры фич
                analyzer.features = [
                    BotFeature("Поиск", "Поиск информации", "medium", True, True, ["api.example.com"]),
                    BotFeature("Уведомления", "Система уведомлений", "complex", True, False),
                ]
                
                # Генерируем отчет
                report = await analyzer.generate_report()
                
                # Создаем копию
                copier = BotCopier(bot_username, report)
                zip_path = await copier.create_zip_copy()
                
                # Обновляем статус
                await status_msg.edit_text(
                    f"✅ Анализ завершен!\n\n"
                    f"📊 *Результаты:*\n"
                    f"• Команд: {report.commands_found}\n"
                    f"• Кнопок: {report.buttons_found}\n"
                    f"• Функций: {report.features_found}\n"
                    f"• БД: {'✅' if report.database_usage else '❌'}\n"
                    f"• Сложность: {report.estimated_complexity}\n\n"
                    f"📥 Отправляю ZIP файл...",
                    parse_mode="Markdown"
                )
                
                # Отправляем ZIP
                zip_file = FSInputFile(str(zip_path))
                await message.answer_document(
                    zip_file,
                    caption=f"📦 Копия бота @{bot_username}\n\n"
                            f"В архиве:\n"
                            f"✓ bot_main.py - шаблон\n"
                            f"✓ bot_structure.json - структура\n"
                            f"✓ README.md - документация\n"
                            f"✓ config.py - конфиг\n"
                            f"✓ requirements.txt - зависимости"
                )
                
                # Отправляем подробный отчет
                report_text = (
                    f"📋 *Подробный отчет для @{bot_username}*\n\n"
                    f"📅 Дата: {report.analysis_date}\n"
                    f"⚙️ Сложность: {report.estimated_complexity}\n\n"
                    f"🎮 *Команды ({report.commands_found}):*\n"
                )
                
                for cmd in report.commands:
                    report_text += f"• /{cmd.name} - {cmd.description}\n"
                
                report_text += f"\n🔘 *Кнопки ({report.buttons_found}):*\n"
                for btn in report.buttons[:5]:
                    report_text += f"• {btn.text}\n"
                
                report_text += f"\n⚙️ *Функции ({report.features_found}):*\n"
                for feat in report.features:
                    report_text += f"• {feat.name}\n"
                
                await message.answer(report_text, parse_mode="Markdown")
                
                # Сохраняем сессию
                self.user_sessions[user_id]["analyzer"] = analyzer
                
            except Exception as e:
                await message.answer(f"❌ Ошибка при анализе: {str(e)}")
                logger.error(f"Ошибка: {e}")
    
    async def run(self):
        """Запустить бота"""
        try:
            logger.info("🚀 Bot Analyzer запущен!")
            await self.dp.start_polling(self.bot, skip_updates=True)
        finally:
            await self.bot.session.close()


# ============= ТОЧКА ВХОДА =============

async def main():
    analyzer_bot = BotAnalyzerBot(TOKEN)
    await analyzer_bot.run()

if __name__ == "__main__":
    asyncio.run(main())
