"""Logger setup per ARCHITECTURE.md §9.

Single logger named ``zerotrust``. Format:
    %(asctime)s | %(levelname)s | %(name)s | %(message)s

Sensitive values (private keys, plaintext, session keys, pre-master) MUST
NEVER be passed to the logger. Call sites are responsible for redaction;
this module provides only the wiring.
"""

from __future__ import annotations

import logging
import os
from logging import Logger
from pathlib import Path

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
ROOT_NAME = "zerotrust"


def get_logger(name: str | None = None, *, log_file: str | os.PathLike | None = None,
               level: int = logging.INFO) -> Logger:
    """Return a configured child logger under ``zerotrust``.

    On first call for a given file path, attaches a FileHandler. Idempotent:
    repeated calls do not duplicate handlers.
    """
    root = logging.getLogger(ROOT_NAME)
    if not root.handlers:
        # Always have a stream handler so tests / dev runs see output.
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(stream)
    root.setLevel(level)

    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Avoid attaching the same file handler twice.
        already = any(
            isinstance(h, logging.FileHandler) and Path(h.baseFilename) == path.resolve()
            for h in root.handlers
        )
        if not already:
            fh = logging.FileHandler(path)
            fh.setFormatter(logging.Formatter(LOG_FORMAT))
            root.addHandler(fh)

    if name is None:
        return root
    return root.getChild(name)


def fingerprint(blob: bytes) -> str:
    """Return the first 16 hex chars of SHA-256(blob).

    Per ARCHITECTURE.md §9, certificate / key fingerprints are logged in this
    redacted form, never the full key material.
    """
    import hashlib
    return hashlib.sha256(blob).hexdigest()[:16]
