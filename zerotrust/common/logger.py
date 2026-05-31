"""Logger setup per ARCHITECTURE.md §9.

Single logger named ``zerotrust``. Format:
    %(asctime)s | %(levelname)s | %(name)s | %(message)s

Sensitive values (private keys, plaintext, session keys, pre-master) MUST
NEVER be passed to the logger. Call sites are responsible for redaction;
this module provides only the wiring.

This module also exposes a small structured-audit helper (:func:`audit`)
used by the server-side handler/handshake per issue #20. The format is
deliberately ``event=<id> key=value key=value ...`` so the audit file is
both human-grepable and machine-parsable, and so the test in
``test_audit_log.py`` can scan it with a Forbidden-list regex.

Forbidden in any log line (ARCHITECTURE.md §9 sensitive-data
isolation):

* Private keys / PEM bytes
* Plaintext file contents
* ``pre_master`` / ``c2s_key`` / ``s2c_key`` / ``transcript_hash`` raw bytes
* Unwrapped AES file keys
* Full signatures (only the first 8 hex chars of a sha256 are OK)
* Passwords (CA password, user password, ``ZEROTRUST_*_PASSWORD`` env values)

:func:`audit` enforces this *defensively*: any bytes argument is replaced
with its ``fingerprint(...)`` (16 hex chars), and field names matching the
forbidden list are dropped with a ``<redacted>`` marker. The caller is
still responsible for not passing plaintext as a string — Python can't
tell a "username" string from a "decrypted-file" string.
"""

from __future__ import annotations

import logging
import os
from logging import Logger
from pathlib import Path
from typing import Any

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
ROOT_NAME = "zerotrust"

# Field names that must NEVER appear in a log line, no matter how a caller
# tries to spell them. Lowercased for case-insensitive comparison.
_FORBIDDEN_FIELDS = frozenset({
    "private_key", "priv_pem", "private_pem", "priv_key",
    "plaintext", "file_plaintext", "plain",
    "pre_master", "premaster", "pre_master_secret",
    "c2s_key", "s2c_key", "session_key", "aes_key", "file_key",
    "transcript_hash", "transcript",
    "password", "passphrase",
    "signature",  # only fingerprints/short prefixes are OK
    "ciphertext",  # only ciphertext fingerprints, not raw bytes
    "wrapped_key",
    "public_key_pem", "cert_pem", "pem",
})


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


# ---------------------------------------------------------------------------
# Structured audit helper (issue #20)
# ---------------------------------------------------------------------------

_MAX_FIELD_LEN = 256


def _safe_value(name: str, value: Any) -> str:
    """Render *value* for log output. Defensive against sensitive types.

    * ``bytes`` → ``fingerprint(value)`` so raw key material can never leak.
    * Strings longer than :data:`_MAX_FIELD_LEN` are truncated with a marker
      (a multi-megabyte ciphertext accidentally passed as a string would
      flood the audit file and almost certainly contain attacker-controlled
      bytes).
    * Whitespace inside string values is collapsed to ``_`` so the
      ``key=value`` grammar stays parseable; ``=`` becomes ``%3D``.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"fp={fingerprint(bytes(value))}"
    if value is None:
        return "-"
    text = str(value)
    if len(text) > _MAX_FIELD_LEN:
        text = text[:_MAX_FIELD_LEN] + "...[truncated]"
    # Keep the ``key=value key=value`` shape robust under hostile input.
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    text = text.replace(" ", "_").replace("=", "%3D")
    return text


def audit(
    log: Logger,
    level: int,
    event: str,
    /,
    **fields: Any,
) -> None:
    """Emit a structured audit event.

    The line shape is ``event=<event> key=value key=value ...`` so the
    audit file is grep-friendly *and* every event line begins with the
    same prefix.

    Forbidden field names (see :data:`_FORBIDDEN_FIELDS`) are dropped and
    replaced with ``<name>=<redacted>``. ``bytes``-typed values are
    fingerprinted in place — passing ``signature=<raw bytes>`` is a
    common mistake and we want it to remain harmless.
    """
    parts = [f"event={event}"]
    for key, value in fields.items():
        if key.lower() in _FORBIDDEN_FIELDS:
            parts.append(f"{key}=<redacted>")
            continue
        parts.append(f"{key}={_safe_value(key, value)}")
    log.log(level, " ".join(parts))


def audit_info(log: Logger, event: str, /, **fields: Any) -> None:
    """``audit`` at ``INFO`` — the normal success path."""
    audit(log, logging.INFO, event, **fields)


def audit_warning(log: Logger, event: str, /, **fields: Any) -> None:
    """``audit`` at ``WARNING`` — auth fails, replay, expired, unauthorised."""
    audit(log, logging.WARNING, event, **fields)


def audit_error(log: Logger, event: str, /, **fields: Any) -> None:
    """``audit`` at ``ERROR`` — signature fail, malformed, internal errors."""
    audit(log, logging.ERROR, event, **fields)
