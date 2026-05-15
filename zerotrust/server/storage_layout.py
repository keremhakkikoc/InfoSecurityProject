"""Server-side storage layout helpers.

Where on disk things live, and the safety rails (regex boundary) that
keep filesystem operations from being driven by client input.
"""

from __future__ import annotations

import json
import os
import re

# The ONLY pattern accepted for a username in path-building helpers.
# Anchored, ASCII, length-bounded — explicit defence against `../`,
# null bytes, slashes, and oversized input. AI.md §3 boundary.
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def pubkey_path_for(storage_base: str, username: str) -> str:
    """Return the on-disk path of a user's CA-signed cert JSON.

    Does NOT validate ``username``; callers MUST check with
    ``USERNAME_REGEX`` first. Layout:

        <storage_base>/pubkeys/<username>.json
    """
    return os.path.join(storage_base, "pubkeys", f"{username}.json")


def load_pubkey_cert(storage_base: str, username: str) -> dict | None:
    """Load and JSON-parse the stored cert dict, or return None.

    Any read / parse failure surfaces as None — callers translate that
    into a generic NOT_FOUND on the wire (no filesystem leak).
    """
    path = pubkey_path_for(storage_base, username)
    try:
        with open(path, encoding="utf-8") as f:
            cert = json.load(f)
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
        return None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(cert, dict):
        return None
    return cert