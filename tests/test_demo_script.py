from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "demo" / "run_demo.sh"


def test_demo_script_exists_and_is_executable():
    assert SCRIPT.is_file()
    mode = SCRIPT.stat().st_mode
    assert os.access(SCRIPT, os.X_OK) or mode & stat.S_IXUSR


def test_demo_script_lints_with_bash_n():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    subprocess.run([bash, "-n", str(SCRIPT)], check=True)


def test_demo_script_references_canonical_make_targets():
    text = SCRIPT.read_text(encoding="utf-8")
    for target in ("ca-init", "ca-issue", "client-setup", "server-register"):
        assert f"make {target}" in text
