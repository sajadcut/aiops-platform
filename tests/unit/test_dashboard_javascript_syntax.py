import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_javascript_syntax():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node runtime unavailable for JavaScript syntax validation")
    scripts = sorted((ROOT / "dashboards").glob("*.js"))
    assert scripts
    for script in scripts:
        result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, f"{script}: {result.stderr}"
