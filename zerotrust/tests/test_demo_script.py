"""Static checks for the demo orchestrator (issue #28).

The full demo is intentionally **not** executed in CI: it spins up a real
TCP server in the background, mints a CA, and writes to disk — too slow
and too stateful for a unit test. Instead, we statically assert the
script exists, is executable, parses cleanly under `bash -n`, and still
references every Makefile target it depends on. If anyone renames one
of those targets, this test fails on the next push instead of silently
breaking the grader's demo.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SCRIPT = REPO_ROOT / "demo" / "run_demo.sh"

# Targets the demo orchestrator must keep calling. If one of these
# disappears or gets renamed, the demo silently rots — this list
# anchors the script to the Makefile.
REQUIRED_MAKE_TARGETS = (
    "ca-init",
    "ca-issue",
    "client-setup",
    "server-register",
    "clean",
)


def test_demo_script_exists_and_is_executable() -> None:
    assert DEMO_SCRIPT.is_file(), f"missing {DEMO_SCRIPT}"
    mode = DEMO_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, "demo/run_demo.sh is not user-executable"


def test_demo_script_has_bash_shebang() -> None:
    first_line = DEMO_SCRIPT.read_text(encoding="utf-8").splitlines()[0]
    # Either form is acceptable; we just refuse a script with no shebang
    # because `bash demo/run_demo.sh` would mask portability bugs.
    assert first_line.startswith("#!"), "demo/run_demo.sh missing shebang"
    assert "bash" in first_line, f"unexpected shebang: {first_line!r}"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_demo_script_passes_bash_syntax_check() -> None:
    """`bash -n` parses the script without executing it."""
    result = subprocess.run(
        ["bash", "-n", str(DEMO_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"bash -n failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )


def test_demo_script_uses_strict_mode() -> None:
    """A demo orchestrator without `set -euo pipefail` will hide failures."""
    body = DEMO_SCRIPT.read_text(encoding="utf-8")
    assert "set -euo pipefail" in body, (
        "demo/run_demo.sh must run under `set -euo pipefail`"
    )


def test_demo_script_installs_a_trap() -> None:
    """The script must guarantee the background server is killed on exit."""
    body = DEMO_SCRIPT.read_text(encoding="utf-8")
    assert "trap " in body, "demo/run_demo.sh must install a cleanup trap"


@pytest.mark.parametrize("target", REQUIRED_MAKE_TARGETS)
def test_demo_script_references_make_target(target: str) -> None:
    body = DEMO_SCRIPT.read_text(encoding="utf-8")
    assert f"make {target}" in body, (
        f"demo/run_demo.sh no longer invokes 'make {target}' — "
        "either the script or the Makefile drifted."
    )


def test_demo_sample_file_is_present_and_small() -> None:
    sample = REPO_ROOT / "demo" / "sample_files" / "report.pdf"
    assert sample.is_file(), "demo/sample_files/report.pdf missing"
    # Pitfall guard from the issue: keep sample inputs under 100 KB.
    assert sample.stat().st_size <= 100 * 1024, (
        "demo sample file exceeded the 100 KB cap from the issue"
    )


def test_demo_expected_output_present() -> None:
    """expected_output.txt is referenced by demo/README.md and must exist."""
    expected = REPO_ROOT / "demo" / "expected_output.txt"
    assert expected.is_file(), "demo/expected_output.txt missing"
    body = expected.read_text(encoding="utf-8")
    # Sanity: the success banner the runner prints must be in the
    # reference output so the grader knows what to look for.
    assert "Plaintext match" in body
