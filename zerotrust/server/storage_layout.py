"""Server storage path layout per ARCHITECTURE.md §4.1.

Centralises every place the server resolves a filesystem path so the
username-sanitisation regex (the security boundary against ``../``
traversal) lives in exactly one module. Callers MUST go through
:func:`pubkey_path_for` / :func:`files_dir` / :func:`pubkeys_dir` rather
than building paths inline.

Pitfall from issue #22 — the regex IS the boundary. Anchor it
(``^...$``), reject dots, slashes, and null bytes. ``re.fullmatch`` enforces
the anchoring even if a caller forgets to include ``^`` / ``$``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Whitelist of allowed characters in a username on disk. Anything else
# (dots, slashes, null bytes, leading ``-`` followed by command-flag tricks
# downstream) is rejected before any filesystem access — see
# :func:`valid_username` below.
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def valid_username(username: Any) -> bool:
    """Return True iff *username* is safe to use in a file path.

    Used by both the GET_PUBKEY handler (recipient lookup) and the
    UPLOAD_REQUEST handler (recipient-existence check). A False here means
    the caller should surface ``NOT_FOUND`` to the client — never a
    distinct "invalid username" error, because that would leak which
    inputs the regex rejects.
    """
    return isinstance(username, str) and _USERNAME_RE.fullmatch(username) is not None


def storage_dir(server_state: dict[str, Any]) -> Path:
    """Return the root storage directory for the running server.

    Explicit ``server_state["storage_dir"]`` wins; otherwise the parent of
    ``db_path`` is used so tests can point a tmp dir at everything by
    setting only ``db_path``.
    """
    configured = server_state.get("storage_dir")
    if configured is not None:
        return Path(configured)
    return Path(server_state.get("db_path", "server/storage/metadata.db")).parent


def pubkeys_dir(server_state: dict[str, Any]) -> Path:
    """Return ``<storage>/pubkeys/`` (override: ``pubkeys_dir``)."""
    configured = server_state.get("pubkeys_dir")
    if configured is not None:
        return Path(configured)
    return storage_dir(server_state) / "pubkeys"


def files_dir(server_state: dict[str, Any]) -> Path:
    """Return ``<storage>/files/`` (override: ``files_dir``)."""
    configured = server_state.get("files_dir")
    if configured is not None:
        return Path(configured)
    return storage_dir(server_state) / "files"


def pubkey_path_for(server_state: dict[str, Any], username: str) -> Path | None:
    """Return the on-disk path of ``username``'s pubkey cert, or ``None``.

    Returns ``None`` (NOT the constructed path) if *username* fails the
    regex — callers MUST treat ``None`` as ``NOT_FOUND`` to the client.
    """
    if not valid_username(username):
        return None
    return pubkeys_dir(server_state) / f"{username}.json"


def file_blob_path_for(server_state: dict[str, Any], file_id: str) -> Path:
    """Return ``<files>/<file_id>.bin`` for a UUID-shaped ``file_id``.

    ``file_id`` is the server-internal identifier minted at upload time,
    not a user-controlled string, so there is no traversal risk — but we
    still keep the helper here so disk layout stays in one place.
    """
    return files_dir(server_state) / f"{file_id}.bin"


__all__ = [
    "valid_username",
    "storage_dir",
    "pubkeys_dir",
    "files_dir",
    "pubkey_path_for",
    "file_blob_path_for",
]
