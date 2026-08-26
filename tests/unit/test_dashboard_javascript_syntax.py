import shutil
import subprocess
from pathlib import Path

import pytest


def test_control_center_javascript_syntax():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node runtime unavailable for JavaScript syntax validation")
    script = Path("dashboards/control-center.js")
    result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
