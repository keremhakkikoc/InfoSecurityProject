"""Replay protection cache per ARCHITECTURE.md §7.8 + §6.

* Reject if ``abs(now - msg.timestamp) > 30s`` (STALE)
* Reject if nonce is already in ``seen_nonces`` (REPLAY)
* On accept, insert nonce into ``seen_nonces``

The cleanup thread is the responsibility of ``server/main.py`` (Phase 3
issue #27); it deletes nonces older than 5 minutes.

Frozen signature (per ARCHITECTURE.md §10.1):

    check_and_record(conn, nonce: bytes, timestamp: int) -> bool
"""

from __future__ import annotations

import sqlite3
import time

# Window per ARCHITECTURE.md §7.8.
TIMESTAMP_WINDOW_SECONDS = 30
NONCE_RETENTION_SECONDS = 300


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS seen_nonces (
    nonce   BLOB PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_seen_at ON seen_nonces(seen_at);
"""


def init_schema(conn: sqlite3.Connection) -> None:
    """Create the ``seen_nonces`` table if it does not exist."""
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def check_and_record(conn: sqlite3.Connection, nonce: bytes, timestamp: int) -> bool:
    """Return True iff (nonce, timestamp) is fresh and not seen before.

    On True, the nonce is recorded atomically. The caller is expected to use
    its own thread-local sqlite3 connection (ARCHITECTURE.md §5).
    """
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 16:
        return False
    now = int(time.time())
    if abs(now - int(timestamp)) > TIMESTAMP_WINDOW_SECONDS:
        return False
    try:
        with conn:  # transaction
            conn.execute(
                "INSERT INTO seen_nonces(nonce, seen_at) VALUES (?, ?)",
                (bytes(nonce), now),
            )
    except sqlite3.IntegrityError:
        # nonce was already in the cache — replay
        return False
    return True


def purge_old_nonces(conn: sqlite3.Connection,
                    *, retention_seconds: int = NONCE_RETENTION_SECONDS) -> int:
    """Delete nonces older than the retention window. Returns rows deleted."""
    cutoff = int(time.time()) - retention_seconds
    with conn:
        cur = conn.execute("DELETE FROM seen_nonces WHERE seen_at < ?", (cutoff,))
        return cur.rowcount
