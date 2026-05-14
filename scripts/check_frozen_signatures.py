#!/usr/bin/env python3
"""Enforce ARCHITECTURE.md §10.1 frozen function signatures.

Imports each contract function at runtime and compares its ``inspect.signature``
against the values locked in below. Any drift fails CI.

Adding a new parameter — even an optional one — counts as drift here, because
``def f(x, y=None)`` is a different contract from ``def f(x)``. If a real
change is necessary, update both ``EXPECTED`` below AND ARCHITECTURE.md §10.1
in the same PR, and notify the team in the PR description.

Run locally:
    python scripts/check_frozen_signatures.py
"""

from __future__ import annotations

import importlib
import inspect
import sys
from pathlib import Path
from typing import Any

# Ensure the repo root is on sys.path so ``zerotrust`` is importable when
# this script is invoked from anywhere.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# (module_path, attr_name, expected_signature_string)
#
# The expected signature uses the *exact* string produced by
# ``str(inspect.signature(fn))``. Run the script once and copy what it
# reports if a deliberate change is approved.
EXPECTED: list[tuple[str, str, str]] = [
    # common.crypto_primitives
    ("zerotrust.common.crypto_primitives", "generate_rsa_keypair",
     "(password: bytes) -> tuple[bytes, bytes]"),
    ("zerotrust.common.crypto_primitives", "rsa_sign",
     "(private_pem: bytes, password: bytes, data: bytes) -> bytes"),
    ("zerotrust.common.crypto_primitives", "rsa_verify",
     "(public_pem: bytes, data: bytes, signature: bytes) -> bool"),
    ("zerotrust.common.crypto_primitives", "rsa_oaep_encrypt",
     "(public_pem: bytes, data: bytes) -> bytes"),
    ("zerotrust.common.crypto_primitives", "rsa_oaep_decrypt",
     "(private_pem: bytes, password: bytes, data: bytes) -> bytes"),
    ("zerotrust.common.crypto_primitives", "aes_gcm_encrypt",
     "(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]"),
    ("zerotrust.common.crypto_primitives", "aes_gcm_decrypt",
     "(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes"),
    ("zerotrust.common.crypto_primitives", "hkdf_derive",
     "(ikm: bytes, salt: bytes, info: bytes, length: int, extra: str = '') -> bytes"),

    # ca.cert
    ("zerotrust.ca.cert", "issue_certificate",
     "(subject: str, subject_pubkey_pem: bytes, ca_priv_pem: bytes, "
     "ca_password: bytes, validity_days: int = 365) -> dict"),
    ("zerotrust.ca.cert", "verify_certificate",
     "(cert: dict, ca_pubkey_pem: bytes, expected_subject: str | None = None) -> bool"),

    # common.protocol
    ("zerotrust.common.protocol", "pack_message", "(msg: dict) -> bytes"),
    ("zerotrust.common.protocol", "recv_message", "(sock: socket.socket) -> dict"),
    ("zerotrust.common.protocol", "make_envelope",
     "(msg_type: str, payload: dict) -> dict"),

    # server.replay
    ("zerotrust.server.replay", "check_and_record",
     "(conn: sqlite3.Connection, nonce: bytes, timestamp: int) -> bool"),
]


def actual_signature(module_path: str, attr: str) -> str:
    mod = importlib.import_module(module_path)
    fn: Any = getattr(mod, attr)
    # ``eval_str=True`` (3.10+) resolves PEP-563 string annotations to real
    # types so the output matches the EXPECTED form ``int`` rather than
    # the literal string ``'int'``.
    return str(inspect.signature(fn, eval_str=True))


def main() -> int:
    failures: list[tuple[str, str, str]] = []
    for module_path, attr, expected in EXPECTED:
        try:
            actual = actual_signature(module_path, attr)
        except Exception as exc:  # noqa: BLE001 — report and continue
            failures.append((f"{module_path}.{attr}", expected,
                             f"<could not import: {exc}>"))
            continue
        if actual != expected:
            failures.append((f"{module_path}.{attr}", expected, actual))

    if failures:
        print("FAIL: frozen signature drift detected\n")
        for name, expected, actual in failures:
            print(f"  {name}")
            print(f"    expected: {expected}")
            print(f"    actual:   {actual}")
            print()
        print("If this change is intentional, update both EXPECTED in this "
              "file AND ARCHITECTURE.md §10.1 in the same PR, and call it "
              "out in the PR description.")
        return 1
    print(f"OK: {len(EXPECTED)} frozen signatures match the contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
