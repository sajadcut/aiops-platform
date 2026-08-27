from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "CODE_SYMBOLS_FA.md"


def tracked_files() -> list[str]:
    result = subprocess.run(["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True)
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def _purpose(name: str, kind: str, doc: str | None) -> str:
    if doc:
        first = " ".join(doc.strip().splitlines()[0].split())
        return first.replace("|", "/")
    low = name.lower()
    rules = [
        (("get_", "list_", "read_", "load", "fetch", "search"), "داده را بدون تغییر state بازیابی/فهرست می‌کند"),
        (("save", "store", "persist", "write", "insert", "update"), "state یا داده را به‌صورت durable ذخیره/به‌روزرسانی می‌کند"),
        (("validate", "check", "verify"), "شرط/قرارداد را بررسی و نتیجه validation برمی‌گرداند"),
        (("create", "build", "make", "normalize", "resolve"), "یک ساختار canonical می‌سازد یا ورودی را normalize/resolve می‌کند"),
        (("execute", "run", "remediate"), "مسیر اجرای عملیات را از boundary مربوطه عبور می‌دهد"),
        (("approve", "reject", "consume"), "transition مربوط به Approval/Governance را اعمال می‌کند"),
        (("route", "dispatch", "select"), "بر اساس state/capability مسیر یا handler مناسب را انتخاب می‌کند"),
        (("collect", "gather", "query"), "Evidence/داده موردنیاز را از منبع مربوط جمع می‌کند"),
        (("evaluate", "score", "rank"), "کیفیت/confidence یا اولویت را به‌صورت deterministic محاسبه می‌کند"),
        (("render", "show"), "خروجی UI/نمایشی را می‌سازد"),
        (("test_",), "Regression/contract مورد نام‌برده را در pytest اثبات می‌کند"),
    ]
    for prefixes, purpose in rules:
        if low.startswith(prefixes):
            return purpose
    return "کلاس" if kind == "class" else "تابع/متد با مسئولیت مشخص‌شده توسط نام و فایل میزبان"


def python_symbols(path: str) -> list[tuple[str, int, str, str, str]]:
    source = (ROOT / path).read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return [("<syntax-error>", 0, "parse-error", "فایل Python قابل parse نیست", "—")]

    rows: list[tuple[str, int, str, str, str]] = []

    def walk(body: list[ast.stmt], parent: str = "") -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                qualified = f"{parent}.{node.name}" if parent else node.name
                rows.append((qualified, node.lineno, "class", _purpose(node.name, "class", ast.get_docstring(node)), parent or "module"))
                walk(node.body, qualified)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{parent}.{node.name}" if parent else node.name
                kind = "async method" if parent and isinstance(node, ast.AsyncFunctionDef) else "method" if parent else "async function" if isinstance(node, ast.AsyncFunctionDef) else "function"
                rows.append((qualified, node.lineno, kind, _purpose(node.name, "function", ast.get_docstring(node)), parent or "module"))
                # nested functions نیز بخشی از behavior هستند و عمداً index می‌شوند.
                walk(node.body, qualified)

    walk(tree.body)
    return rows


_JS_FUNCTION = re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(")
_JS_ASSIGN = re.compile(r"\b(?:window\.)?([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\(")
_JS_ARROW = re.compile(r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?[^;\n=]*=>")


def js_symbols(path: str) -> list[tuple[str, int, str, str, str]]:
    source = (ROOT / path).read_text(encoding="utf-8")
    rows = []
    seen = set()
    for lineno, line in enumerate(source.splitlines(), 1):
        for regex in (_JS_FUNCTION, _JS_ASSIGN, _JS_ARROW):
            for match in regex.finditer(line):
                name = match.group(1)
                if (name, lineno) in seen:
                    continue
                seen.add((name, lineno))
                rows.append((name, lineno, "JavaScript function", _purpose(name, "function", None), "browser module"))
    return rows


def render() -> str:
    files = tracked_files()
    rows: list[tuple[str, str, int, str, str, str]] = []
    python_file_count = 0
    js_file_count = 0
    for path in files:
        if path.endswith(".py"):
            python_file_count += 1
            rows.extend((path, *item) for item in python_symbols(path))
        elif path.startswith("dashboards/") and path.endswith(".js"):
            js_file_count += 1
            rows.extend((path, *item) for item in js_symbols(path))

    lines = [
        "# CODE SYMBOLS فارسی — aiops-platform",
        "",
        "> این سند به‌صورت deterministic از source code ساخته می‌شود و class/function/methodهای Python و functionهای JavaScript داشبورد را index می‌کند.",
        "> هدف، پیدا کردن سریع مسئولیت هر symbol است؛ توضیح معماری عمیق‌تر در `CODEBASE_GUIDE_FA.md` قرار دارد.",
        "",
        f"**Python files scanned: {python_file_count} | Dashboard JS files scanned: {js_file_count} | Symbols indexed: {len(rows)}**",
        "",
        "| File | Symbol | Line | Kind | Purpose | Parent/Context |",
        "|---|---|---:|---|---|---|",
    ]
    for path, symbol, line, kind, purpose, parent in rows:
        vals = [path, symbol, str(line), kind, purpose, parent]
        vals = [v.replace("|", "/") for v in vals]
        lines.append(f"| `{vals[0]}` | `{vals[1]}` | {vals[2]} | {vals[3]} | {vals[4]} | {vals[5]} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    expected = render()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
