"""Smoke tests for the client CLI login bootstrap."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from zerotrust.client import cli
from zerotrust.common.exceptions import CryptoError


class FakeSocket:
    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _write_client_dir(root: Path, username: str = "alice") -> Path:
    client_dir = root / f"client_{username}"
    client_dir.mkdir()
    (client_dir / "config.json").write_text(
        json.dumps({
            "server_host": "127.0.0.1",
            "server_port": 5050,
            "username": username,
            "server_subject": "server-01",
        }),
        encoding="utf-8",
    )
    (client_dir / "cert.json").write_text(
        json.dumps({"subject": username, "public_key_pem": "client-pub"}),
        encoding="utf-8",
    )
    (client_dir / "ca_cert.json").write_text(
        json.dumps({"public_key_pem": "ca-pub"}),
        encoding="utf-8",
    )
    (client_dir / "private.pem").write_bytes(b"encrypted-private-pem")
    return client_dir


def test_argparse_accepts_documented_command_shapes():
    parser = cli.build_parser()

    assert parser.parse_args(["--user", "alice", "login"]).command == "login"

    upload = parser.parse_args(["--user", "alice", "upload", "bob", "msg.txt"])
    assert upload.command == "upload"
    assert upload.recipient == "bob"
    assert upload.file == "msg.txt"

    assert parser.parse_args(["--user", "alice", "list"]).command == "list"

    download = parser.parse_args(["--user", "alice", "download", "file-123"])
    assert download.command == "download"
    assert download.file_id == "file-123"


def test_missing_user_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["login"])
    assert excinfo.value.code == 2


def test_login_loads_assets_and_calls_handshake(tmp_path, monkeypatch, capsys):
    _write_client_dir(tmp_path)
    monkeypatch.chdir(tmp_path)

    created_connections: list[tuple[tuple[str, int], float | None]] = []
    handshake_calls: list[dict[str, Any]] = []

    def fake_create_connection(address: tuple[str, int], timeout: float | None = None):
        created_connections.append((address, timeout))
        return FakeSocket()

    def fake_handshake(**kwargs: Any) -> dict[str, Any]:
        handshake_calls.append(kwargs)
        return {
            "peer_subject": "server-01",
            "peer_cert": {},
            "c2s_key": b"c" * 32,
            "s2c_key": b"s" * 32,
            "transcript_hash": b"t" * 32,
        }

    monkeypatch.setattr(
        "zerotrust.client.session.socket.create_connection",
        fake_create_connection,
    )
    monkeypatch.setattr(
        "zerotrust.client.session.perform_client_handshake",
        fake_handshake,
    )

    rc = cli.main(["--user", "alice", "--password", "secret", "login"])

    out = capsys.readouterr()
    assert rc == 0
    assert out.err == ""
    assert out.out == "Authenticated as alice; session established with server-01.\n"
    assert created_connections == [(("127.0.0.1", 5050), 5.0)]

    assert len(handshake_calls) == 1
    call = handshake_calls[0]
    assert call["client_cert"]["subject"] == "alice"
    assert call["client_priv_pem"] == b"encrypted-private-pem"
    assert call["client_password"] == b"secret"
    assert call["ca_pubkey_pem"] == b"ca-pub"
    assert call["expected_server_subject"] == "server-01"


def test_login_uses_env_password(tmp_path, monkeypatch):
    _write_client_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZEROTRUST_USER_PASSWORD", "from-env")

    monkeypatch.setattr(
        "zerotrust.client.session.socket.create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )

    captured_passwords: list[bytes] = []

    def fake_handshake(**kwargs: Any) -> dict[str, Any]:
        captured_passwords.append(kwargs["client_password"])
        return {"peer_subject": "server-01"}

    monkeypatch.setattr(
        "zerotrust.client.session.perform_client_handshake",
        fake_handshake,
    )

    assert cli.main(["--user", "alice", "login"]) == 0
    assert captured_passwords == [b"from-env"]


def test_login_auth_failure_prints_generic_error(tmp_path, monkeypatch, capsys):
    _write_client_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "zerotrust.client.session.socket.create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )
    monkeypatch.setattr(
        "zerotrust.client.session.perform_client_handshake",
        lambda **_kwargs: (_ for _ in ()).throw(CryptoError("wrong password")),
    )

    rc = cli.main(["--user", "alice", "--password", "wrong", "login"])

    out = capsys.readouterr()
    assert rc == 1
    assert out.out == ""
    assert out.err == "AUTH_FAILED\n"
    assert "wrong password" not in out.err


def test_login_missing_cert_prints_clear_error(tmp_path, monkeypatch, capsys):
    client_dir = _write_client_dir(tmp_path)
    (client_dir / "cert.json").unlink()
    monkeypatch.chdir(tmp_path)

    rc = cli.main(["--user", "alice", "--password", "secret", "login"])

    out = capsys.readouterr()
    assert rc == 1
    assert out.out == ""
    assert out.err == "client_alice/cert.json not found\n"


def test_login_connection_refused_is_clean(tmp_path, monkeypatch, capsys):
    _write_client_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "zerotrust.client.session.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ConnectionRefusedError("connection refused")
        ),
    )

    rc = cli.main(["--user", "alice", "--password", "secret", "login"])

    out = capsys.readouterr()
    assert rc == 1
    assert out.out == ""
    assert "connection refused" in out.err
