import ast
import re
from collections import Counter
from typing import Any


class IntegratedAnalyzer:
    """Безопасный статический анализатор. Никогда не выполняет загруженный код."""

    SECRET_PATTERNS = [
        (re.compile(r'(?i)(bot[_-]?token|api[_-]?key|secret[_-]?key)\s*=\s*["\'][^"\']{8,}["\']'),
         "Возможный секрет/токен в исходном коде"),
        (re.compile(r'(?i)password\s*=\s*["\'][^"\']+["\']'),
         "Пароль захардкожен в исходном коде"),
        (re.compile(r'(?i)eval\s*\('), "Используется eval()"),
        (re.compile(r'(?i)exec\s*\('), "Используется exec()"),
        (re.compile(r'(?i)subprocess\.(run|Popen|call|check_output)\s*\('),
         "Вызов subprocess требует проверки входных данных"),
    ]

    def __init__(self, code: str, language: str = "py"):
        self.code = code
        self.language = language.lower()

    def security(self):
        issues = []
        for line_no, line in enumerate(self.code.splitlines(), 1):
            for pattern, description in self.SECRET_PATTERNS:
                if pattern.search(line):
                    severity = "critical" if any(x in description.lower() for x in ("токен", "пароль", "eval", "exec")) else "high"
                    issues.append({
                        "severity": severity,
                        "line": line_no,
                        "description": description,
                        "suggestion": "Используй переменные окружения и безопасные API вместо захардкоженных секретов."
                    })
        return issues

    def performance(self):
        issues = []
        lines = self.code.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'for\s+\w+\s+in\s+range\(\s*\d{5,}', line):
                issues.append({"line": i, "description": "Большой цикл может быть дорогим по CPU."})
            if ".append(" in line and "for " in line:
                issues.append({"line": i, "description": "Проверь возможность использовать comprehension или более эффективную структуру."})
        return issues[:50]

    def complexity(self):
        score = 1
        if self.language in ("py", "python"):
            try:
                tree = ast.parse(self.code)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Match)):
                        score += 1
                    if isinstance(node, ast.BoolOp):
                        score += max(0, len(node.values) - 1)
            except SyntaxError:
                score = 0
        else:
            score = 1 + len(re.findall(r'\b(if|for|while|case|catch)\b', self.code))
        if score <= 5:
            level = "Низкая"
        elif score <= 10:
            level = "Средняя"
        else:
            level = "Высокая"
        return {"score": score, "level": level}

    def style(self):
        lines = self.code.splitlines()
        issues = 0
        for line in lines:
            if len(line) > 120:
                issues += 1
            if line.rstrip() != line:
                issues += 1
        score = max(0, 100 - min(100, issues * 5))
        return {"score": score, "total_issues": issues}

    def dependencies(self):
        imports = Counter()
        if self.language in ("py", "python"):
            try:
                tree = ast.parse(self.code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports[alias.name.split(".")[0]] += 1
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports[node.module.split(".")[0]] += 1
            except SyntaxError:
                pass
        else:
            for mod in re.findall(r'\b(?:import|from|require)\s+[\'"]?([A-Za-z0-9_.-]+)', self.code):
                imports[mod.split(".")[0]] += 1

        std = {"os","sys","json","re","math","time","asyncio","logging","pathlib","typing","datetime","collections","itertools","functools","sqlite3"}
        standard = sum(v for k, v in imports.items() if k in std)
        third = sum(v for k in imports if k not in std and not k.startswith("."))
        local = sum(v for k in imports if k.startswith("."))
        return {
            "standard_library": standard,
            "third_party": third,
            "local": local,
            "modules": dict(imports)
        }

    def run_full_analysis(self) -> dict[str, Any]:
        sec = self.security()
        perf = self.performance()
        comp = self.complexity()
        style = self.style()
        deps = self.dependencies()

        critical = sum(x["severity"] == "critical" for x in sec)
        high = sum(x["severity"] == "high" for x in sec)
        security_score = max(0, 100 - critical * 25 - high * 10)

        if security_score >= 90:
            grade = "A+"
        elif security_score >= 80:
            grade = "A"
        elif security_score >= 70:
            grade = "B"
        elif security_score >= 60:
            grade = "C"
        elif security_score >= 50:
            grade = "D"
        else:
            grade = "F"

        return {
            "overall_grade": f"{grade} ({security_score}/100)",
            "security": sec,
            "security_report": {
                "security_score": security_score,
                "grade": grade,
                "critical": critical,
                "high": high,
                "medium": 0,
            },
            "performance": perf,
            "performance_report": {"total_issues": len(perf)},
            "complexity": comp,
            "style": style,
            "dependencies": deps,
        }
