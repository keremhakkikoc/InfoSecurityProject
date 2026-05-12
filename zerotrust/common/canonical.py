"""Canonical JSON serialisation for content that will be signed.

ARCHITECTURE.md §3.2 and AI.md §2 mandate ``sort_keys=True`` and
``separators=(",", ":")`` for **any** JSON before signing or verification.
Even a single byte of whitespace difference invalidates the signature, so
all signing/verifying code paths MUST go through this module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Return the canonical UTF-8 byte representation of *obj*."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_sha256_hex(obj: Any) -> str:
    """SHA-256 hex digest of the canonical JSON encoding of *obj*."""
    return hashlib.sha256(canonical_json(obj)).hexdigest()
