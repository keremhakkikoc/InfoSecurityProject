"""SQLite-backed metadata store (Phase 2 — issue #14).

Schema lives in ARCHITECTURE.md §5; this module is a stub that Phase 2
fills in. Each thread MUST open its own ``sqlite3.Connection`` per
ARCHITECTURE.md §5/§6.
"""

from __future__ import annotations

import sqlite3


def open_connection(db_path: str) -> sqlite3.Connection:
    """Open a fresh per-thread SQLite connection (Phase 2 stub)."""
    raise NotImplementedError("server.store.open_connection — Phase 2 issue #14")


def init_schema(conn: sqlite3.Connection) -> None:
    """Create the ``files``, ``seen_nonces``, ``acks`` tables (Phase 2 stub)."""
    raise NotImplementedError("server.store.init_schema — Phase 2 issue #14")


def insert_file(conn: sqlite3.Connection, row: dict) -> None:
    raise NotImplementedError("server.store.insert_file — Phase 2 issue #14")


def list_pending_for(conn: sqlite3.Connection, recipient: str) -> list[dict]:
    raise NotImplementedError("server.store.list_pending_for — Phase 3 issue #15")


def get_file(conn: sqlite3.Connection, file_id: str) -> dict | None:
    raise NotImplementedError("server.store.get_file — Phase 3 issue #16")


def mark_status(conn: sqlite3.Connection, file_id: str, status: str) -> None:
    raise NotImplementedError("server.store.mark_status — Phase 3 issue #16")
