import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _check_javascript(node: str, source: str, label: str, tmp_path: Path) -> None:
    candidate = tmp_path / f"{re.sub(r'[^a-zA-Z0-9_.-]+', '_', label)}.js"
    candidate.write_text(source, encoding="utf-8")
    result = subprocess.run([node, "--check", str(candidate)], capture_output=True, text=True)
    assert result.returncode == 0, f"{label}: {result.stderr}"


def test_dashboard_javascript_syntax(tmp_path: Path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node runtime unavailable for JavaScript syntax validation")

    scripts = sorted((ROOT / "dashboards").glob("*.js"))
    assert scripts
    for script in scripts:
        result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, f"{script}: {result.stderr}"

    html_files = sorted((ROOT / "dashboards").glob("*.html"))
    inline_count = 0
    for html in html_files:
        source = html.read_text(encoding="utf-8")
        for index, match in enumerate(re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", source, flags=re.I | re.S), start=1):
            inline_count += 1
            _check_javascript(node, match.group(1), f"{html.name}-inline-{index}", tmp_path)
    assert inline_count > 0
