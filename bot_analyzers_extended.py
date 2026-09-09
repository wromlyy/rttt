"""
🔬 РАСШИРЕННЫЕ АНАЛИЗАТОРЫ ДЛЯ БОТОВ
Дополнительные инструменты для глубокого анализа
"""

import re
import json
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


# ============= ENUM И DATACLASSES =============

class SecurityLevel(Enum):
    """Уровни безопасности"""
    CRITICAL = "🔴 Критично"
    HIGH = "🟠 Высокий"
    MEDIUM = "🟡 Средний"
    LOW = "🟢 Низкий"
    INFO = "🔵 Информация"


class Complexity(Enum):
    """Уровни сложности"""
    TRIVIAL = "Элементарный"
    SIMPLE = "Простой"
    MEDIUM = "Средний"
    COMPLEX = "Сложный"
    VERY_COMPLEX = "Очень сложный"


@dataclass
class SecurityIssue:
    """Проблема безопасности"""
    level: SecurityLevel
    type: str
    description: str
    line_number: int = 0
    suggestion: str = ""
    code_snippet: str = ""


@dataclass
class PerformanceIssue:
    """Проблема производительности"""
    type: str
    description: str
    severity: str  # low, medium, high
    suggestion: str


# ============= АНАЛИЗАТОР БЕЗОПАСНОСТИ =============

class SecurityAnalyzer:
    """Анализирует безопасность кода бота"""
    
    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.patterns = {
            # Опасные функции
            "eval": (SecurityLevel.CRITICAL, "Использование eval()"),
            "exec": (SecurityLevel.CRITICAL, "Использование exec()"),
            "__import__": (SecurityLevel.HIGH, "Динамический импорт"),
            "compile": (SecurityLevel.HIGH, "Компиляция кода во время выполнения"),
            
            # Проблемы с БД
            "f\"SELECT": (SecurityLevel.CRITICAL, "SQL Injection риск (f-string)"),
            "f'SELECT": (SecurityLevel.CRITICAL, "SQL Injection риск (f-string)"),
            ".format(": (SecurityLevel.HIGH, "SQL Injection риск (.format)"),
            
            # Сохранение чувствительных данных
            "TOKEN = ": (SecurityLevel.HIGH, "Токен захардкожен"),
            "PASSWORD = ": (SecurityLevel.HIGH, "Пароль захардкожен"),
            "API_KEY = ": (SecurityLevel.HIGH, "API ключ захардкожен"),
            
            # Небезопасные операции
            "os.system": (SecurityLevel.HIGH, "Использование os.system()"),
            "subprocess.call": (SecurityLevel.HIGH, "Использование subprocess без проверки"),
            "pickle.loads": (SecurityLevel.HIGH, "Небезопасная десериализация"),
            
            # Отсутствие проверок
            "except:": (SecurityLevel.MEDIUM, "Слишком общий except"),
            "except Exception": (SecurityLevel.MEDIUM, "Слишком общий Exception catch"),
        }
    
    def analyze(self, code_content: str) -> List[SecurityIssue]:
        """Анализировать код на проблемы безопасности"""
        self.issues = []
        lines = code_content.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, (level, desc) in self.patterns.items():
                if pattern in line and not line.strip().startswith("#"):
                    issue = SecurityIssue(
                        level=level,
                        type=desc,
                        description=f"Обнаружено в строке {line_num}",
                        line_number=line_num,
                        code_snippet=line.strip()
                    )
                    
                    # Добавляем рекомендации
                    if "SQL" in desc:
                        issue.suggestion = "Используй параметризованные запросы (?)  или ORM"
                    elif "TOKEN" in desc or "PASSWORD" in desc or "API_KEY" in desc:
                        issue.suggestion = "Используй переменные окружения или .env файл"
                    elif "pickle" in desc:
                        issue.suggestion = "Используй json вместо pickle для данных от пользователя"
                    elif "eval" in desc or "exec" in desc:
                        issue.suggestion = "Переписать без использования eval/exec"
                    elif "except:" in desc:
                        issue.suggestion = "Ловить конкретные исключения (except ValueError, TypeError:)"
                    
                    self.issues.append(issue)
        
        return self.issues
    
    def get_security_report(self) -> Dict[str, Any]:
        """Получить отчет о безопасности"""
        critical = sum(1 for i in self.issues if i.level == SecurityLevel.CRITICAL)
        high = sum(1 for i in self.issues if i.level == SecurityLevel.HIGH)
        medium = sum(1 for i in self.issues if i.level == SecurityLevel.MEDIUM)
        
        score = 100 - (critical * 20 + high * 10 + medium * 5)
        score = max(0, min(100, score))
        
        return {
            "total_issues": len(self.issues),
            "critical": critical,
            "high": high,
            "medium": medium,
            "security_score": score,
            "grade": self._get_grade(score),
            "issues": [
                {
                    "level": issue.level.value,
                    "type": issue.type,
                    "line": issue.line_number,
                    "suggestion": issue.suggestion,
                    "code": issue.code_snippet,
                }
                for issue in self.issues
            ]
        }
    
    @staticmethod
    def _get_grade(score: int) -> str:
        """Получить оценку безопасности"""
        if score >= 90:
            return "A+ 🟢"
        elif score >= 80:
            return "A 🟢"
        elif score >= 70:
            return "B 🟡"
        elif score >= 50:
            return "C 🟠"
        else:
            return "D 🔴"


# ============= АНАЛИЗАТОР ПРОИЗВОДИТЕЛЬНОСТИ =============

class PerformanceAnalyzer:
    """Анализирует производительность кода"""
    
    def __init__(self):
        self.issues: List[PerformanceIssue] = []
    
    def analyze(self, code_content: str) -> List[PerformanceIssue]:
        """Анализировать код на проблемы производительности"""
        self.issues = []
        lines = code_content.split("\n")
        
        # Поиск синхронных операций
        for i, line in enumerate(lines):
            # Проверка на блокирующие операции в async функции
            if "async def" in lines[max(0, i-10):i]:  # Проверяем контекст
                if any(x in line for x in ["time.sleep", "requests.", "open("]):
                    self.issues.append(PerformanceIssue(
                        type="Blocking operation in async",
                        description=f"Блокирующая операция в async функции: {line.strip()}",
                        severity="high",
                        suggestion="Используй await asyncio.sleep(), aiohttp, aiofiles и т.д."
                    ))
            
            # Проверка на утечки памяти
            if "while True:" in line:
                self.issues.append(PerformanceIssue(
                    type="Infinite loop",
                    description=f"Бесконечный цикл может привести к утечкам",
                    severity="medium",
                    suggestion="Добавь условие выхода или используй async/await"
                ))
            
            # Проверка на большие циклы
            if "for" in line and "range(" in line:
                # Пытаемся извлечь диапазон
                match = re.search(r'range\((\d+)\)', line)
                if match:
                    num = int(match.group(1))
                    if num > 10000:
                        self.issues.append(PerformanceIssue(
                            type="Large loop",
                            description=f"Большой цикл на {num} итераций может быть медленным",
                            severity="medium",
                            suggestion="Рассмотри использование батчинга или асинхронной обработки"
                        ))
            
            # Проверка на N+1 запросы
            if "for" in line:
                for next_line in lines[i:i+10]:
                    if any(x in next_line for x in ["query", "select", "api.get", "requests.get"]):
                        self.issues.append(PerformanceIssue(
                            type="Potential N+1 query",
                            description="Возможна проблема N+1 запросов в цикле",
                            severity="high",
                            suggestion="Используй batch запросы или join вместо циклических запросов"
                        ))
                        break
        
        return self.issues
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Получить отчет о производительности"""
        high = sum(1 for i in self.issues if i.severity == "high")
        medium = sum(1 for i in self.issues if i.severity == "medium")
        low = sum(1 for i in self.issues if i.severity == "low")
        
        return {
            "total_issues": len(self.issues),
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "issues": [
                {
                    "type": issue.type,
                    "description": issue.description,
                    "severity": issue.severity,
                    "suggestion": issue.suggestion,
                }
                for issue in self.issues
            ]
        }


# ============= АНАЛИЗАТОР СЛОЖНОСТИ =============

class ComplexityAnalyzer:
    """Анализирует цикломатическую сложность"""
    
    @staticmethod
    def calculate_cyclomatic_complexity(code_content: str) -> Dict[str, Any]:
        """Вычислить цикломатическую сложность"""
        complexity_score = 1  # базовая сложность
        
        # Считаем точки принятия решений
        decisions = {
            "if ": 1,
            "elif ": 1,
            "else": 0,  # не добавляет сложность сам по себе
            "for ": 1,
            "while ": 1,
            "except": 1,
            "and": 0.5,
            "or": 0.5,
            "?": 1,  # тернарный оператор
            "lambda": 1,
        }
        
        for keyword, weight in decisions.items():
            complexity_score += code_content.count(keyword) * weight
        
        complexity_score = int(complexity_score)
        
        # Определяем уровень
        if complexity_score <= 5:
            level = Complexity.SIMPLE
        elif complexity_score <= 10:
            level = Complexity.MEDIUM
        elif complexity_score <= 20:
            level = Complexity.COMPLEX
        else:
            level = Complexity.VERY_COMPLEX
        
        return {
            "score": complexity_score,
            "level": level.value,
            "description": ComplexityAnalyzer._get_complexity_advice(complexity_score)
        }
    
    @staticmethod
    def _get_complexity_advice(score: int) -> str:
        """Получить рекомендацию по сложности"""
        if score <= 5:
            return "Код легко понять и поддерживать ✅"
        elif score <= 10:
            return "Код имеет нормальную сложность. Рассмотри рефакторинг ⚠️"
        elif score <= 20:
            return "Код сложный. Настоятельно рекомендуется рефакторинг 🔴"
        else:
            return "Код слишком сложный. Срочно требуется рефакторинг! 🔴🔴"


# ============= АНАЛИЗАТОР КОДА STYLE =============

class CodeStyleAnalyzer:
    """Анализирует стиль кода (PEP8)"""
    
    @staticmethod
    def analyze(code_content: str) -> Dict[str, Any]:
        """Анализировать стиль кода"""
        issues = []
        
        lines = code_content.split("\n")
        
        for i, line in enumerate(lines, 1):
            # Проверка длины линии
            if len(line) > 100:
                issues.append({
                    "type": "Line too long",
                    "line": i,
                    "message": f"Строка {len(line)} символов (максимум 100)",
                    "severity": "low"
                })
            
            # Проверка отступов (должны быть 4 пробела)
            if line and line[0] == " ":
                indent = len(line) - len(line.lstrip())
                if indent % 4 != 0:
                    issues.append({
                        "type": "Invalid indentation",
                        "line": i,
                        "message": f"Отступ {indent} пробелов (должно быть кратно 4)",
                        "severity": "medium"
                    })
            
            # Проверка на пробелы вокруг операторов
            if "==" in line or "!=" in line:
                if " == " not in line and "==" in line:
                    issues.append({
                        "type": "Missing spaces",
                        "line": i,
                        "message": "Нет пробелов вокруг оператора",
                        "severity": "low"
                    })
            
            # Проверка переменных в snake_case
            if "def " in line:
                vars = re.findall(r'(\w+)\s*:', line)
                for var in vars:
                    if var != var.lower() and "_" not in var:
                        issues.append({
                            "type": "Variable naming",
                            "line": i,
                            "message": f"Переменная '{var}' должна быть в snake_case",
                            "severity": "low"
                        })
        
        return {
            "total_issues": len(issues),
            "issues": issues,
            "score": max(0, 100 - len(issues) * 2)
        }


# ============= АНАЛИЗАТОР ЗАВИСИМОСТЕЙ =============

class DependencyAnalyzer:
    """Анализирует зависимости между модулями"""
    
    @staticmethod
    def analyze(code_content: str) -> Dict[str, Any]:
        """Анализировать зависимости"""
        
        imports = {
            "standard": [],
            "third_party": [],
            "local": []
        }
        
        # Стандартные библиотеки Python
        standard_libs = {
            "os", "sys", "json", "re", "datetime", "time", "random",
            "math", "asyncio", "threading", "subprocess", "pathlib",
            "collections", "itertools", "functools", "typing",
        }
        
        for line in code_content.split("\n"):
            if line.strip().startswith(("import ", "from ")):
                # Извлекаем название модуля
                match = re.match(r'(?:from\s+(\S+)|import\s+(\S+))', line)
                if match:
                    module = match.group(1) or match.group(2)
                    module = module.split('.')[0]
                    
                    if module in standard_libs:
                        if module not in imports["standard"]:
                            imports["standard"].append(module)
                    elif module.startswith('.'):
                        if module not in imports["local"]:
                            imports["local"].append(module)
                    else:
                        if module not in imports["third_party"]:
                            imports["third_party"].append(module)
        
        return {
            "standard_library": len(imports["standard"]),
            "third_party": len(imports["third_party"]),
            "local": len(imports["local"]),
            "total_dependencies": sum(len(v) for v in imports.values()),
            "imports": imports,
            "health": "Good" if len(imports["third_party"]) < 20 else "Warning: Many dependencies"
        }


# ============= ИНТЕГРИРОВАННЫЙ АНАЛИЗАТОР =============

class IntegratedAnalyzer:
    """Интегрирует все анализаторы"""
    
    def __init__(self, code_content: str):
        self.code = code_content
        self.security_analyzer = SecurityAnalyzer()
        self.performance_analyzer = PerformanceAnalyzer()
        self.complexity_analyzer = ComplexityAnalyzer()
        self.style_analyzer = CodeStyleAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """Запустить полный анализ кода"""
        
        return {
            "security": self.security_analyzer.analyze(self.code),
            "security_report": self.security_analyzer.get_security_report(),
            
            "performance": self.performance_analyzer.analyze(self.code),
            "performance_report": self.performance_analyzer.get_performance_report(),
            
            "complexity": self.complexity_analyzer.calculate_cyclomatic_complexity(self.code),
            
            "style": self.style_analyzer.analyze(self.code),
            
            "dependencies": self.dependency_analyzer.analyze(self.code),
            
            "overall_grade": self._calculate_overall_grade()
        }
    
    def _calculate_overall_grade(self) -> str:
        """Вычислить общую оценку"""
        security_score = 100 - len(self.security_analyzer.issues) * 5
        
        grades = {
            90: "A+",
            80: "A",
            70: "B",
            60: "C",
            50: "D",
            0: "F"
        }
        
        for threshold, grade in sorted(grades.items(), reverse=True):
            if security_score >= threshold:
                return f"{grade} ({security_score}/100)"
        
        return "F (0/100)"
    
    def export_to_json(self, filepath: str = None) -> str:
        """Экспортировать отчет в JSON"""
        analysis = self.run_full_analysis()
        
        # Конвертируем Security Issues в dict
        analysis["security"] = [
            {
                "level": issue.level.value,
                "type": issue.type,
                "line": issue.line_number,
                "description": issue.description,
                "suggestion": issue.suggestion,
            }
            for issue in analysis["security"]
        ]
        
        json_str = json.dumps(analysis, ensure_ascii=False, indent=2)
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(json_str)
        
        return json_str
    
    def export_to_html(self) -> str:
        """Экспортировать отчет в HTML"""
        analysis = self.run_full_analysis()
        
        html = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #007bff; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .score {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Отчет о Анализе Кода</h1>
        
        <div class="section">
            <h2>Overall Grade</h2>
            <div class="score">{analysis['overall_grade']}</div>
        </div>
        
        <div class="section">
            <h2>🔐 Безопасность</h2>
            <p>Score: {analysis['security_report']['security_score']}/100 ({analysis['security_report']['grade']})</p>
            <p>Issues: 🔴 {analysis['security_report']['critical']} | 🟠 {analysis['security_report']['high']} | 🟡 {analysis['security_report']['medium']}</p>
        </div>
        
        <div class="section">
            <h2>⚡ Производительность</h2>
            <p>Issues: {analysis['performance_report']['total_issues']}</p>
        </div>
        
        <div class="section">
            <h2>📐 Сложность</h2>
            <p>Cyclomatic Complexity: {analysis['complexity']['score']}</p>
            <p>Level: {analysis['complexity']['level']}</p>
            <p>{analysis['complexity']['description']}</p>
        </div>
        
        <div class="section">
            <h2>🎨 Стиль Кода</h2>
            <p>Score: {analysis['style']['score']}/100</p>
            <p>Issues: {analysis['style']['total_issues']}</p>
        </div>
        
        <div class="section">
            <h2>📦 Зависимости</h2>
            <p>Standard Library: {analysis['dependencies']['standard_library']}</p>
            <p>Third Party: {analysis['dependencies']['third_party']}</p>
            <p>Local: {analysis['dependencies']['local']}</p>
        </div>
    </div>
</body>
</html>
"""
        return html


# ============= ТОЧКА ВХОДА =============

if __name__ == "__main__":
    # Пример использования
    sample_code = """
import os
import sys

def slow_function():
    for i in range(100000):
        if i % 2 == 0:
            print(i)
        else:
            print(i*2)

TOKEN = "123456:ABC-DEF"  # Опасно!
"""
    
    analyzer = IntegratedAnalyzer(sample_code)
    report = analyzer.run_full_analysis()
    
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
