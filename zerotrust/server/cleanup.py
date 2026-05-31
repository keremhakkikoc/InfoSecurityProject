"""Background maintenance loop (ARCHITECTURE.md §6, issue #27).

Once a minute the server runs a single cleanup pass that:

1. Deletes ``seen_nonces`` rows older than 5 minutes (replay-cache GC —
   the freshness window is only 30 seconds, so anything older can no
   longer be replayed and the row is dead weight).
2. Flips ``files`` rows from ``status='pending'`` to ``'expired'`` once
   ``expiration < now()``. ``mark_expired`` only touches pending rows,
   so already-downloaded or already-expired files are left alone.

Both ``run_cleanup_pass`` and ``start_cleanup_thread`` accept a
``clock`` callable so tests can force-advance time without monkey-patching
the global ``time`` module. The thread itself is a daemon —
it must never block process shutdown.

The loop is fail-tolerant: a transient SQLite or filesystem error during
one pass is logged and the loop continues. A bad pass must not silently
stop maintenance.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable

from . import replay, store

logger = logging.getLogger(__name__)

#: How often the loop wakes up, per ARCHITECTURE.md §6 (every 60 seconds).
DEFAULT_INTERVAL_SECONDS = 60


def run_cleanup_pass(
    conn: sqlite3.Connection,
    *,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> tuple[int, int]:
    """Run one maintenance pass and return ``(nonces_deleted, files_expired)``.

    Pure DB work — no socket I/O — so it is safe to call from tests with
    an in-memory connection. The cleanup thread calls this once per tick.
    """
    now = int(clock())
    # purge_old_nonces uses the global clock internally; tests that need to
    # force-advance can stage rows directly. Both helpers commit on success.
    nonces_deleted = replay.purge_old_nonces(conn)
    files_expired = store.mark_expired(conn, now=now)
    return nonces_deleted, files_expired


def _cleanup_loop(
    db_path: str,
    stop_event: threading.Event,
    interval: float,
    clock: Callable[[], int],
) -> None:
    """Body of the daemon thread; loops until ``stop_event`` is set."""
    logger.info("[cleanup] started (interval=%ss, db=%s)", interval, db_path)
    # Each thread opens its own sqlite3 connection; we never share
    # a connection across threads.
    conn: sqlite3.Connection | None = None
    try:
        conn = store.open_connection(db_path)
        store.init_schema(conn)
        replay.init_schema(conn)

        while not stop_event.is_set():
            try:
                nonces, files = run_cleanup_pass(conn, clock=clock)
                logger.info(
                    "[cleanup] pass complete: nonces_deleted=%d files_expired=%d",
                    nonces, files,
                )
            except sqlite3.Error:
                # A locked / disk-full DB on one tick must not kill the loop.
                logger.exception("[cleanup] pass failed; continuing")
            except Exception:  # noqa: BLE001
                logger.exception("[cleanup] unexpected error; continuing")

            # ``Event.wait`` returns True as soon as stop is set, so the
            # thread shuts down promptly during graceful shutdown.
            if stop_event.wait(interval):
                break
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        logger.info("[cleanup] stopped")


def start_cleanup_thread(
    db_path: str,
    *,
    stop_event: threading.Event | None = None,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> tuple[threading.Thread, threading.Event]:
    """Launch the cleanup daemon and return ``(thread, stop_event)``.

    The caller signals shutdown by calling ``stop_event.set()`` and then
    ``thread.join(timeout)``. The thread is started as a daemon so a
    forgotten ``set()`` cannot block interpreter exit.
    """
    if stop_event is None:
        stop_event = threading.Event()

    thread = threading.Thread(
        target=_cleanup_loop,
        args=(db_path, stop_event, interval, clock),
        name="zerotrust-cleanup",
        daemon=True,
    )
    thread.start()
    return thread, stop_event
