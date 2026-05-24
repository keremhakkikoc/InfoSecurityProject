"""Tests for LIST_PENDING / PENDING_LIST (issue #15)."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.download import list_pending
from zerotrust.client.session import connected_session
from zerotrust.client.upload import upload_file
from zerotrust.common import crypto_primitives as cp
from zerotrust.server.store import mark_expired
from zerotrust.tests.test_upload import (
    ALICE_PASSWORD,
    BOB_PASSWORD,
    _Env,
    _running_server,
    env,
)

CAROL_PASSWORD = b"carol-test-password"


def _write_config(env: _Env, username: str, port: int) -> Path:
    if username not in ["alice", "bob"]:
        # For Carol, we need to create her assets first
        carol_priv, carol_pub = cp.generate_rsa_keypair(CAROL_PASSWORD)
        carol_cert = cert_mod.issue_certificate(
            "carol", carol_pub, env.ca_priv, b"ca-test-password"
        )
        env._write_pubkey("carol", carol_cert)

        cdir = env.tmp / "client_carol"
        cdir.mkdir(exist_ok=True)
        (cdir / "ca_cert.json").write_text(json.dumps(env.ca_cert))
        (cdir / "cert.json").write_text(json.dumps(carol_cert))
        (cdir / "private.pem").write_bytes(carol_priv)
    else:
        cdir = env.write_client_dir(username)

    (cdir / "config.json").write_text(json.dumps({
        "server_host": "127.0.0.1",
        "server_port": port,
        "username": username,
        "server_subject": "zerotrust-server",
    }))
    return cdir


def test_pending_list_happy_and_isolation(env, monkeypatch):
    """Happy path + Isolation: Alice uploads to Bob -> Carol's list is empty."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        _write_config(env, "bob", port)
        _write_config(env, "carol", port)

        file_path = env.tmp / "report.txt"
        file_path.write_bytes(b"secret_data")

        # Alice uploads to Bob
        with connected_session("alice", ALICE_PASSWORD) as session:
            ack = upload_file(session, "bob", str(file_path))
            file_id = ack["file_id"]

        # Bob's list shows exactly one row with the right file_id
        with connected_session("bob", BOB_PASSWORD) as session:
            bob_list = list_pending(session)
            assert len(bob_list) == 1
            assert bob_list[0]["file_id"] == file_id
            assert bob_list[0]["sender_id"] == "alice"
            assert bob_list[0]["ciphertext_size"] > 0

        # Isolation: Carol's list returns []
        with connected_session("carol", CAROL_PASSWORD) as session:
            carol_list = list_pending(session)
            assert len(carol_list) == 0

        # Empty inbox returns PENDING_LIST with files=[], not an error (Carol's was empty)
        assert carol_list == []


def test_pending_list_expired_filter(env, monkeypatch):
    """Expired files do NOT appear in the listing."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        _write_config(env, "bob", port)

        file_path = env.tmp / "report.txt"
        file_path.write_bytes(b"secret_data")
        
        with connected_session("alice", ALICE_PASSWORD) as session:
            upload_file(session, "bob", str(file_path))

        # Check it is there before expiration
        with connected_session("bob", BOB_PASSWORD) as session:
            assert len(list_pending(session)) == 1

        # Force expire the row in the DB
        conn = sqlite3.connect(str(env.db_path))
        try:
            # The background thread marks it expired when now > expiration
            # We advance time by 8 days (upload default expiration is 7 days)
            mark_expired(conn, now=int(time.time()) + 8 * 86400)
        finally:
            conn.close()

        # Should be omitted from listing
        with connected_session("bob", BOB_PASSWORD) as session:
            assert len(list_pending(session)) == 0


def test_pending_list_replay_is_idempotent(env, monkeypatch):
    """Replay (cheap): two listings in a row both succeed."""
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        _write_config(env, "alice", port)
        
        with connected_session("alice", ALICE_PASSWORD) as session:
            # The session handles nonce generation automatically for each request
            # so these are technically distinct envelopes, but it proves LIST_PENDING
            # can be called multiple times without side effects (idempotent).
            list1 = list_pending(session)
            list2 = list_pending(session)
            
            assert list1 == []
            assert list2 == []
