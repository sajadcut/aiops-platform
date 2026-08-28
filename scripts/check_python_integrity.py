from __future__ import annotations

import ast
import importlib.metadata
import importlib.util
import re
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_FILES = (ROOT / "requirements.txt", ROOT / "requirements-dev.txt")
SKIP_PARTS = {".git", ".pytest_cache", "__pycache__", ".venv", "venv", "site-packages"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?", line)
    return _norm(match.group(1)) if match else None


def _python_files() -> Iterable[Path]:
    for path in ROOT.rglob("*.py"):
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        yield path


def _local_top_level_modules() -> set[str]:
    modules: set[str] = set()
    for child in ROOT.iterdir():
        if child.name.startswith("."):
            continue
        if child.is_file() and child.suffix == ".py":
            modules.add(child.stem)
        elif child.is_dir() and any(child.rglob("*.py")):
            modules.add(child.name)
    return modules


def main() -> int:
    errors: list[str] = []
    imported_top_levels: set[str] = set()
    python_files = sorted(_python_files())

    for path in python_files:
        rel = path.relative_to(ROOT)
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(rel))
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"syntax:{rel}:{exc}")
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_top_levels.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported_top_levels.add(node.module.split(".", 1)[0])

    declared: set[str] = set()
    for requirement_file in REQUIREMENT_FILES:
        if not requirement_file.exists():
            errors.append(f"requirements_file_missing:{requirement_file.name}")
            continue
        declared.update(
            name
            for line in requirement_file.read_text(encoding="utf-8").splitlines()
            if (name := _requirement_name(line))
        )

    installed = {_norm(dist.metadata["Name"]) for dist in importlib.metadata.distributions() if dist.metadata.get("Name")}
    missing_declared = sorted(declared - installed)
    for name in missing_declared:
        errors.append(f"declared_requirement_not_installed:{name}")

    local_modules = _local_top_level_modules()
    stdlib = set(sys.stdlib_module_names)
    package_to_distributions = importlib.metadata.packages_distributions()

    for module in sorted(imported_top_levels):
        if module in local_modules or module in stdlib or module == "__future__":
            continue
        try:
            spec = importlib.util.find_spec(module)
        except (ImportError, AttributeError, ValueError) as exc:
            errors.append(f"unresolved_import:{module}:{type(exc).__name__}:{exc}")
            continue
        if spec is None:
            errors.append(f"unresolved_import:{module}")
            continue

        distributions = {_norm(name) for name in package_to_distributions.get(module, [])}
        if distributions and not distributions.intersection(declared):
            errors.append(
                "undeclared_direct_dependency:"
                f"{module}:provided_by={','.join(sorted(distributions))}"
            )

    if errors:
        print("Python integrity check FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "Python integrity check OK: "
        f"files={len(python_files)} imports={len(imported_top_levels)} requirements={len(declared)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
