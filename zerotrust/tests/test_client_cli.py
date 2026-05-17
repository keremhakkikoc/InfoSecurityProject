"""Argparse-level smoke tests for ``zerotrust.client.cli`` (issue #15).

The handshake is mocked here on purpose — we want to verify the dispatcher,
password resolution, asset loading, and error mapping without spinning up a
real server. End-to-end coverage lives in the integration tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zerotrust.client import cli as cli_mod
from zerotrust.client import session as session_mod
from zerotrust.client.session import ClientAssetError
from zerotrust.common.exceptions import AuthError, CryptoError


@pytest.fixture
def alice_dir(tmp_path, monkeypatch) -> Path:
    """Lay out a minimal but well-formed client_alice/ directory."""
    monkeypatch.chdir(tmp_path)
    client_dir = tmp_path / "client_alice"
    client_dir.mkdir()

    (client_dir / "config.json").write_text(
        json.dumps({"server_host": "127.0.0.1", "server_port": 9999, "username": "alice"})
    )
    (client_dir / "cert.json").write_text(json.dumps({"subject": "alice"}))
    (client_dir / "ca_cert.json").write_text(
        json.dumps({"public_key_pem": "-----BEGIN PUBLIC KEY-----\nfake\n"})
    )
    (client_dir / "private.pem").write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
    return client_dir


# ---------------------------------------------------------------------------
# Argparse shape — acceptance: documented command shapes accepted
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "argv",
    [
        ["--user", "alice", "login"],
        ["--user", "alice", "upload", "bob", "report.pdf"],
        ["--user", "alice", "list"],
        ["--user", "alice", "download", "file-1"],
    ],
)
def test_argparse_accepts_documented_command_shapes(argv):
    parser = cli_mod.build_parser()
    parsed = parser.parse_args(argv)
    assert parsed.user == "alice"
    assert parsed.command in {"login", "upload", "list", "download"}


def test_missing_user_exits_with_code_two(capsys):
    parser = cli_mod.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["login"])
    assert exc.value.code == 2


def test_missing_subcommand_exits_with_code_two():
    parser = cli_mod.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--user", "alice"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# Login dispatch — handshake mocked
# ---------------------------------------------------------------------------

def test_login_calls_session_with_user_and_password(
    monkeypatch, alice_dir, capsys
):
    captured = {}

    def fake_login(username, password):
        captured["username"] = username
        captured["password"] = password
        return {"peer_subject": "test-server"}

    monkeypatch.setattr(cli_mod, "login_session", fake_login)
    monkeypatch.setenv("ZEROTRUST_USER_PASSWORD", "from-env")

    rc = cli_mod.main(["--user", "alice", "login"])

    assert rc == 0
    assert captured["username"] == "alice"
    assert captured["password"] == b"from-env"
    out = capsys.readouterr().out
    assert "Authenticated as alice" in out
    assert "test-server" in out


def test_login_prefers_password_arg_over_env(monkeypatch, alice_dir):
    captured = {}

    def fake_login(username, password):
        captured["password"] = password
        return {"peer_subject": "srv"}

    monkeypatch.setattr(cli_mod, "login_session", fake_login)
    monkeypatch.setenv("ZEROTRUST_USER_PASSWORD", "env-value")

    rc = cli_mod.main(
        ["--user", "alice", "--password", "cli-value", "login"]
    )
    assert rc == 0
    assert captured["password"] == b"cli-value"


def test_login_falls_back_to_getpass_when_no_arg_or_env(
    monkeypatch, alice_dir
):
    monkeypatch.delenv("ZEROTRUST_USER_PASSWORD", raising=False)
    monkeypatch.setattr(cli_mod.getpass, "getpass", lambda prompt="": "prompted")
    captured = {}

    def fake_login(username, password):
        captured["password"] = password
        return {"peer_subject": "srv"}

    monkeypatch.setattr(cli_mod, "login_session", fake_login)
    rc = cli_mod.main(["--user", "alice", "login"])
    assert rc == 0
    assert captured["password"] == b"prompted"


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------

def test_missing_client_assets_returns_one_with_clear_message(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZEROTRUST_USER_PASSWORD", "pw")

    rc = cli_mod.main(["--user", "alice", "login"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "client_alice" in err
    assert "not found" in err
    assert "AUTH_FAILED" not in err  # filesystem errors are not auth failures


@pytest.mark.parametrize("exc_type", [AuthError, CryptoError])
def test_auth_failures_collapse_to_generic_banner(
    monkeypatch, alice_dir, capsys, exc_type
):
    def fail(username, password):
        raise exc_type("verbose internal reason should not leak")

    monkeypatch.setattr(cli_mod, "login_session", fail)
    monkeypatch.setenv("ZEROTRUST_USER_PASSWORD", "pw")

    rc = cli_mod.main(["--user", "alice", "login"])

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.strip() == "AUTH_FAILED"
    assert "verbose internal reason" not in captured.err
    assert "verbose internal reason" not in captured.out


def test_connection_refused_surfaces_clean_message(
    monkeypatch, alice_dir, capsys
):
    def fail(username, password):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(cli_mod, "login_session", fail)
    monkeypatch.setenv("ZEROTRUST_USER_PASSWORD", "pw")

    rc = cli_mod.main(["--user", "alice", "login"])

    assert rc == 1
    err = capsys.readouterr().err.lower()
    assert "connection refused" in err
    assert "AUTH_FAILED" not in err.upper().replace(err.lower(), err)
    # Make sure we did NOT collapse to AUTH_FAILED for a clean network error.
    assert "auth_failed" not in err


# ---------------------------------------------------------------------------
# session.client_dir_for_user — defensive guards
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["", ".", "..", "../etc", "a/b", "a\\b"])
def test_client_dir_rejects_bad_usernames(bad):
    with pytest.raises(ClientAssetError):
        session_mod.client_dir_for_user(bad)


def test_client_dir_for_valid_username():
    assert session_mod.client_dir_for_user("alice").name == "client_alice"
