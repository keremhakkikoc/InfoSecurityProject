"""Tests for Replay Enforcement (issue #19)."""

from __future__ import annotations

import base64
import json
import sqlite3
import time
from pathlib import Path

import pytest

from zerotrust.client.session import connected_session
from zerotrust.common.protocol import make_envelope, recv_message, send_message, validate_envelope
from zerotrust.server.replay import check_and_record, init_schema
from zerotrust.tests.test_upload import (
    ALICE_PASSWORD,
    _Env,
    _running_server,
    env,
)


def _write_config(env: _Env, username: str, port: int) -> Path:
    cdir = env.write_client_dir(username)
    (cdir / "config.json").write_text(json.dumps({
        "server_host": "127.0.0.1",
        "server_port": port,
        "username": username,
        "server_subject": "zerotrust-server",
    }))
    return cdir


def test_replay_upload_same_socket(env, monkeypatch):
    """Replay upload: send identical envelope twice on same socket -> first MALFORMED/ACK, second STALE."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        
        with connected_session("alice", ALICE_PASSWORD) as session:
            sock = session["sock"]
            # We don't need a perfectly valid upload package to test replay.
            # The replay check is the FIRST thing in the handler.
            # So a valid envelope with garbage payload will hit MALFORMED first, then STALE.
            env_msg = make_envelope("UPLOAD_REQUEST", {"fake": "payload"})
            
            # Send first time
            send_message(sock, env_msg)
            reply1 = validate_envelope(recv_message(sock))
            assert reply1["type"] == "ERROR"
            assert reply1["payload"]["code"] == "MALFORMED"  # because of fake payload
            
            # Send exact same envelope again
            send_message(sock, env_msg)
            reply2 = validate_envelope(recv_message(sock))
            assert reply2["type"] == "ERROR"
            assert reply2["payload"]["code"] == "STALE"  # Replay/Stale are conflated


def test_replay_across_connections(env, monkeypatch):
    """Replay across connections: capture envelope bytes, open fresh socket + handshake, replay -> STALE."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        
        env_msg = make_envelope("UPLOAD_REQUEST", {"fake": "payload"})

        # Connection 1
        with connected_session("alice", ALICE_PASSWORD) as session1:
            send_message(session1["sock"], env_msg)
            reply1 = validate_envelope(recv_message(session1["sock"]))
            assert reply1["payload"]["code"] == "MALFORMED"

        # Connection 2
        with connected_session("alice", ALICE_PASSWORD) as session2:
            send_message(session2["sock"], env_msg)
            reply2 = validate_envelope(recv_message(session2["sock"]))
            assert reply2["payload"]["code"] == "STALE"


def test_stale_timestamp(env, monkeypatch):
    """Stale timestamp: hand-craft envelope with timestamp = now() - 60 -> STALE."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        
        with connected_session("alice", ALICE_PASSWORD) as session:
            sock = session["sock"]
            env_msg = make_envelope("UPLOAD_REQUEST", {})
            env_msg["timestamp"] = int(time.time()) - 60  # 60s in the past
            
            send_message(sock, env_msg)
            reply = validate_envelope(recv_message(sock))
            assert reply["type"] == "ERROR"
            assert reply["payload"]["code"] == "STALE"


def test_future_timestamp(env, monkeypatch):
    """Future timestamp: timestamp = now() + 60 -> STALE."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        
        with connected_session("alice", ALICE_PASSWORD) as session:
            sock = session["sock"]
            env_msg = make_envelope("UPLOAD_REQUEST", {})
            env_msg["timestamp"] = int(time.time()) + 60  # 60s in the future
            
            send_message(sock, env_msg)
            reply = validate_envelope(recv_message(sock))
            assert reply["type"] == "ERROR"
            assert reply["payload"]["code"] == "STALE"


def test_cleanup_interaction(env, monkeypatch):
    """Cleanup interaction: insert a nonce -> fast-forward time.time by 6 minutes -> cleanup deletes it -> same nonce now accepted."""
    monkeypatch.chdir(env.tmp)
    
    # We can test the database cleanup directly since check_and_record relies on it.
    conn = sqlite3.connect(str(env.db_path))
    try:
        init_schema(conn)
        
        nonce = b"1234567890123456"
        now = int(time.time())
        
        # 1. Insert nonce
        assert check_and_record(conn, nonce, now) is True
        
        # 2. Replay immediately fails
        assert check_and_record(conn, nonce, now) is False
        
        # 3. Simulate cleanup thread after 6 minutes
        # We need to delete seen_nonces older than 5 minutes
        with conn:
            conn.execute("DELETE FROM seen_nonces WHERE seen_at < ?", (now - 300,))
            
        # The query above wouldn't delete it because seen_at is 'now', so we need to
        # pretend 6 minutes have passed.
        # If we fast forward by 6 minutes, 'now' is now + 360.
        # The cleanup thread deletes where seen_at < (new_now - 300) = (now + 60)
        # Our nonce was seen at 'now', which is < now + 60, so it gets deleted.
        new_now = now + 360
        with conn:
            conn.execute("DELETE FROM seen_nonces WHERE seen_at < ?", (new_now - 300,))
            
        # 4. Same nonce is now accepted (proves cleanup window works)
        # We must mock time.time() so that check_and_record sees the new time.
        monkeypatch.setattr(time, "time", lambda: new_now)
        
        assert check_and_record(conn, nonce, new_now) is True
        
    finally:
        conn.close()
