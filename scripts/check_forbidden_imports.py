#!/usr/bin/env python3
"""Enforce the bans listed in AI.md §1.11 and ARCHITECTURE.md §2.

This script scans every `.py` file under ``zerotrust/`` (excluding tests and
legacy) and fails CI if any of the following appears:

    - ``import ssl`` / ``from ssl ...``                  (banned in AI.md §1.11)
    - ``import paramiko`` / ``from paramiko ...``        (banned in AI.md §1.11)
    - ``import pickle`` / ``from pickle ...``            (banned in AI.md §6.49)
    - ``import random`` / ``from random ...``            (banned in AI.md §3.27)
    - Literal mentions of ``AES-CBC`` / ``AES-CTR`` /
      ``AES.MODE_CBC`` / ``AES.MODE_CTR`` / ``algorithms.AES`` with CBC/CTR
                                                          (banned in ARCHITECTURE.md §2)
    - ``hashlib.sha1`` / ``hashes.SHA1``                  (banned by SHA-256-only rule)

Pass ``--paths PATH [PATH ...]`` to scan an explicit set instead of the default.
Exit code 0 = clean, 1 = at least one violation. Violations are printed in
``path:line: rule — match`` format so editors can jump straight to the line.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable
from pathlib import Path

DEFAULT_ROOTS = ("zerotrust",)
EXCLUDED_DIRS = {"tests", "__pycache__", ".pytest_cache", "legacy", "venv", ".venv"}

# Each rule: (regex, human-readable reason)
RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*(?:import|from)\s+ssl(?:\s|\.|$)"),
     "AI.md §1.11: ssl module is forbidden (we hand-roll the handshake)"),
    (re.compile(r"^\s*(?:import|from)\s+paramiko(?:\s|\.|$)"),
     "AI.md §1.11: paramiko is a pre-built secure-channel library"),
    (re.compile(r"^\s*(?:import|from)\s+pickle(?:\s|\.|$)"),
     "AI.md §6.49: pickle is forbidden for serialization (use JSON)"),
    (re.compile(r"^\s*(?:import|from)\s+random(?:\s|\.|$)"),
     "AI.md §3.27: use os.urandom / secrets, never the random module"),
    (re.compile(r"\bAES[-_\.]?(?:MODE[_\.])?(?:CBC|CTR)\b"),
     "ARCHITECTURE.md §2: AES-CBC and AES-CTR are forbidden, use AES-GCM"),
    (re.compile(r"\bhashlib\.sha1\b|\bhashes\.SHA1\b"),
     "ARCHITECTURE.md §2: SHA-1 is forbidden, use SHA-256"),
]

# Lines containing this token are exempted (for the rare legitimate case,
# e.g. a comment quoting a banned name when documenting the ban itself).
EXEMPT_TOKEN = "# noqa: forbidden-import"


def iter_python_files(paths: Iterable[str]) -> Iterable[Path]:
    for root in paths:
        p = Path(root)
        if not p.exists():
            continue
        if p.is_file() and p.suffix == ".py":
            yield p
            continue
        for f in p.rglob("*.py"):
            if any(part in EXCLUDED_DIRS for part in f.parts):
                continue
            yield f


def check_file(path: Path) -> list[tuple[int, str, str]]:
    """Return a list of (lineno, reason, match) for every violation."""
    violations: list[tuple[int, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return violations
    for lineno, line in enumerate(text.splitlines(), start=1):
        if EXEMPT_TOKEN in line:
            continue
        # Skip comment-only lines so we can mention banned names in docstrings.
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for pattern, reason in RULES:
            m = pattern.search(line)
            if m:
                violations.append((lineno, reason, m.group(0)))
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--paths", nargs="+", default=list(DEFAULT_ROOTS),
                    help="Root paths to scan (default: zerotrust/)")
    args = ap.parse_args(argv)

    total = 0
    for f in iter_python_files(args.paths):
        for lineno, reason, match in check_file(f):
            print(f"{f}:{lineno}: {reason} — {match!r}")
            total += 1

    if total:
        print(f"\nFAIL: {total} forbidden-import violation(s) found.")
        return 1
    print("OK: no forbidden imports / modes found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
