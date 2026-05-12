"""Tests for server.replay — nonce cache + freshness window."""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

from zerotrust.server import replay


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    replay.init_schema(c)
    yield c
    c.close()


def test_first_use_accepted(conn):
    nonce = os.urandom(16)
    assert replay.check_and_record(conn, nonce, int(time.time())) is True


def test_replayed_nonce_rejected(conn):
    nonce = os.urandom(16)
    now = int(time.time())
    assert replay.check_and_record(conn, nonce, now) is True
    assert replay.check_and_record(conn, nonce, now) is False


def test_stale_timestamp_rejected(conn):
    nonce = os.urandom(16)
    stale = int(time.time()) - 60   # 60s old, window is 30s
    assert replay.check_and_record(conn, nonce, stale) is False


def test_future_timestamp_rejected(conn):
    nonce = os.urandom(16)
    future = int(time.time()) + 60
    assert replay.check_and_record(conn, nonce, future) is False


def test_invalid_nonce_length_rejected(conn):
    assert replay.check_and_record(conn, b"\x00" * 8, int(time.time())) is False


def test_purge_removes_old_entries(conn):
    nonce = os.urandom(16)
    assert replay.check_and_record(conn, nonce, int(time.time())) is True
    # Set seen_at far in the past
    conn.execute("UPDATE seen_nonces SET seen_at = 0 WHERE nonce = ?", (nonce,))
    conn.commit()
    deleted = replay.purge_old_nonces(conn, retention_seconds=300)
    assert deleted == 1


def test_distinct_nonces_independent(conn):
    n1 = os.urandom(16)
    n2 = os.urandom(16)
    now = int(time.time())
    assert replay.check_and_record(conn, n1, now) is True
    assert replay.check_and_record(conn, n2, now) is True
