"""Tests for the background cleanup thread (issue #27).

The acceptance criteria from the issue are:

* Cleanup loop survives server lifetime; logs each pass.
* Tests force-advance the clock and observe state transitions.

We force-advance the clock by:

* injecting a ``clock`` callable into :func:`run_cleanup_pass` (so
  ``mark_expired`` uses the simulated "now" without monkey-patching the
  global ``time`` module), and
* writing ``seen_at`` values directly in the past so that
  ``replay.purge_old_nonces`` (which uses real ``time.time``) deletes
  them deterministically.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time

import pytest

from zerotrust.server import cleanup, replay, store


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    """Per-test in-memory DB with both schemas initialised."""
    c = store.open_connection(":memory:")
    store.init_schema(c)
    replay.init_schema(c)
    yield c
    c.close()


def _base_row(file_id: str, recipient: str, expiration: int, *, status: str = "pending") -> dict:
    return {
        "file_id": file_id,
        "sender_id": "alice",
        "recipient_id": recipient,
        "upload_timestamp": expiration - 3600,
        "expiration": expiration,
        "status": status,
        "ciphertext_path": f"{file_id}.bin",
        "ciphertext_sha256": "deadbeef",
        "wrapped_key": b"k",
        "aes_nonce": b"n",
        "aes_aad": b"a",
        "sender_signature": b"s",
        "sender_cert_json": "{}",
    }


# ---------------------------------------------------------------------------
# store.mark_expired
# ---------------------------------------------------------------------------

class TestMarkExpired:
    def test_pending_past_expiration_flips_to_expired(self, conn):
        now = 1_000_000
        store.insert_file(conn, _base_row("f1", "bob", expiration=now - 1))
        affected = store.mark_expired(conn, now=now)
        assert affected == 1
        assert store.get_file(conn, "f1")["status"] == "expired"

    def test_pending_future_expiration_untouched(self, conn):
        now = 1_000_000
        store.insert_file(conn, _base_row("f1", "bob", expiration=now + 3600))
        affected = store.mark_expired(conn, now=now)
        assert affected == 0
        assert store.get_file(conn, "f1")["status"] == "pending"

    def test_downloaded_row_never_flipped(self, conn):
        """Already-downloaded files keep their audit status, even if expired."""
        now = 1_000_000
        store.insert_file(
            conn,
            _base_row("f1", "bob", expiration=now - 100, status="downloaded"),
        )
        affected = store.mark_expired(conn, now=now)
        assert affected == 0
        assert store.get_file(conn, "f1")["status"] == "downloaded"

    def test_revoked_row_never_flipped(self, conn):
        now = 1_000_000
        store.insert_file(
            conn,
            _base_row("f1", "bob", expiration=now - 100, status="revoked"),
        )
        affected = store.mark_expired(conn, now=now)
        assert affected == 0
        assert store.get_file(conn, "f1")["status"] == "revoked"

    def test_already_expired_row_not_double_processed(self, conn):
        now = 1_000_000
        store.insert_file(
            conn,
            _base_row("f1", "bob", expiration=now - 100, status="expired"),
        )
        affected = store.mark_expired(conn, now=now)
        assert affected == 0

    def test_clock_advance_promotes_pending(self, conn):
        """Force-advance the clock: a pending file flips only once 'now' crosses expiration."""
        expiration = 2_000_000
        store.insert_file(conn, _base_row("f1", "bob", expiration=expiration))

        # Before expiration: nothing changes.
        assert store.mark_expired(conn, now=expiration - 10) == 0
        assert store.get_file(conn, "f1")["status"] == "pending"

        # After expiration: flips to 'expired'.
        assert store.mark_expired(conn, now=expiration + 1) == 1
        assert store.get_file(conn, "f1")["status"] == "expired"

        # Idempotent — a second pass at a later "now" is a no-op.
        assert store.mark_expired(conn, now=expiration + 1000) == 0


# ---------------------------------------------------------------------------
# cleanup.run_cleanup_pass
# ---------------------------------------------------------------------------

class TestRunCleanupPass:
    def test_returns_zero_counts_on_clean_db(self, conn):
        nonces, files = cleanup.run_cleanup_pass(conn, clock=lambda: 1_000_000)
        assert (nonces, files) == (0, 0)

    def test_deletes_old_nonces_and_expires_pending(self, conn):
        # Stage an "old" nonce: insert, then back-date seen_at well past the
        # 5-minute retention window. purge_old_nonces uses time.time(), so we
        # express "old" as `now - retention - margin`.
        nonce = os.urandom(16)
        replay.check_and_record(conn, nonce, int(time.time()))
        conn.execute(
            "UPDATE seen_nonces SET seen_at = ? WHERE nonce = ?",
            (int(time.time()) - 10_000, nonce),
        )
        conn.commit()

        # Stage an expired pending file (clock injection handles the file side).
        sim_now = 5_000_000
        store.insert_file(conn, _base_row("f1", "bob", expiration=sim_now - 1))

        nonces, files = cleanup.run_cleanup_pass(conn, clock=lambda: sim_now)
        assert nonces == 1
        assert files == 1
        assert store.get_file(conn, "f1")["status"] == "expired"

    def test_fresh_nonce_kept(self, conn):
        nonce = os.urandom(16)
        replay.check_and_record(conn, nonce, int(time.time()))
        nonces, _ = cleanup.run_cleanup_pass(conn, clock=lambda: 1_000_000)
        assert nonces == 0
        cur = conn.execute("SELECT COUNT(*) FROM seen_nonces")
        assert cur.fetchone()[0] == 1


# ---------------------------------------------------------------------------
# Background thread lifecycle
# ---------------------------------------------------------------------------

class TestCleanupThread:
    def test_thread_runs_and_stops(self, tmp_path, caplog):
        """Thread starts, completes ≥1 pass, logs it, and joins on stop."""
        db_path = str(tmp_path / "cleanup.db")
        # Seed schema + an expired pending row before the thread starts.
        seed = store.open_connection(db_path)
        store.init_schema(seed)
        replay.init_schema(seed)
        store.insert_file(seed, _base_row("f1", "bob", expiration=10))  # ancient
        seed.close()

        # Force-advance the clock so the pending row is past expiration.
        sim_now = 999_999_999

        # Short interval keeps the test fast; daemon=True means a stuck
        # thread can never wedge pytest.
        with caplog.at_level(logging.INFO, logger="zerotrust.server.cleanup"):
            thread, stop_event = cleanup.start_cleanup_thread(
                db_path,
                interval=0.05,
                clock=lambda: sim_now,
            )
            try:
                # Wait for at least one pass to complete.
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    if any(
                        "pass complete" in rec.message for rec in caplog.records
                    ):
                        break
                    time.sleep(0.05)
                else:
                    pytest.fail("cleanup thread never logged a completed pass")
            finally:
                stop_event.set()
                thread.join(timeout=2.0)

        assert not thread.is_alive(), "cleanup thread did not stop after stop_event"

        # The expired row must have flipped.
        check = store.open_connection(db_path)
        try:
            row = store.get_file(check, "f1")
            assert row is not None and row["status"] == "expired"
        finally:
            check.close()

        # Acceptance criterion: each pass is logged.
        pass_logs = [r for r in caplog.records if "pass complete" in r.message]
        assert pass_logs, "expected at least one 'pass complete' log"

    def test_loop_survives_transient_error(self, tmp_path, caplog, monkeypatch):
        """A failing pass must not kill the loop — the next pass still runs."""
        db_path = str(tmp_path / "cleanup_err.db")
        seed = store.open_connection(db_path)
        store.init_schema(seed)
        replay.init_schema(seed)
        seed.close()

        calls = {"n": 0}
        real_purge = replay.purge_old_nonces

        def flaky_purge(conn, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("simulated transient failure")
            return real_purge(conn, **kw)

        monkeypatch.setattr(cleanup.replay, "purge_old_nonces", flaky_purge)

        with caplog.at_level(logging.INFO, logger="zerotrust.server.cleanup"):
            thread, stop_event = cleanup.start_cleanup_thread(
                db_path, interval=0.05
            )
            try:
                deadline = time.monotonic() + 5.0
                # Wait until we have BOTH a failure log and a subsequent
                # successful pass — proves the loop did not die.
                while time.monotonic() < deadline:
                    msgs = [r.message for r in caplog.records]
                    failed = any("pass failed" in m for m in msgs)
                    succeeded = any("pass complete" in m for m in msgs)
                    if failed and succeeded and calls["n"] >= 2:
                        break
                    time.sleep(0.05)
                else:
                    pytest.fail(
                        f"loop did not recover; calls={calls['n']} "
                        f"msgs={[r.message for r in caplog.records]}"
                    )
            finally:
                stop_event.set()
                thread.join(timeout=2.0)

        assert calls["n"] >= 2, "flaky helper should have been called twice"

    def test_thread_is_daemon(self, tmp_path):
        """Per AI.md / ARCHITECTURE.md §6: background threads must be daemons."""
        db_path = str(tmp_path / "cleanup_daemon.db")
        thread, stop_event = cleanup.start_cleanup_thread(db_path, interval=10)
        try:
            assert thread.daemon is True
            assert thread.name == "zerotrust-cleanup"
        finally:
            stop_event.set()
            thread.join(timeout=2.0)

    def test_stop_event_is_returned_and_honoured(self, tmp_path):
        """Caller-supplied stop_event is reused, not silently replaced."""
        db_path = str(tmp_path / "cleanup_evt.db")
        my_event = threading.Event()
        thread, returned_event = cleanup.start_cleanup_thread(
            db_path, stop_event=my_event, interval=0.05
        )
        try:
            assert returned_event is my_event
            my_event.set()
            thread.join(timeout=2.0)
            assert not thread.is_alive()
        finally:
            if thread.is_alive():
                my_event.set()
                thread.join(timeout=2.0)
