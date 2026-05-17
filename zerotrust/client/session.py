"""Client session bootstrap helpers for the CLI.

Loads the client-side assets described in ARCHITECTURE.md §4.2 and performs
the authenticated handshake from ARCHITECTURE.md §7.4 + §7.5. Future CLI
commands (upload, list, download) re-use ``login_session`` so the session
bootstrap path is a single place to audit.

Per AI.md §3.10 the user password is held in memory for the duration of the
call only — never written to disk, never logged.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from .handshake import perform_client_handshake

DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0


class ClientAssetError(RuntimeError):
    """Raised when ``client_<username>/`` assets are missing or malformed.

    Surfaces a clear, non-secret message (e.g. ``client_alice/cert.json not
    found``) — these are local-filesystem errors, not auth failures, so we
    do NOT collapse them to ``AUTH_FAILED``.
    """


def _display_path(path: Path) -> str:
    return path.as_posix()


def client_dir_for_user(username: str) -> Path:
    """Return ``client_<username>`` after a tight whitelist check."""
    if not username or username in {".", ".."}:
        raise ClientAssetError("invalid username")
    if any(sep in username for sep in ("/", "\\")):
        raise ClientAssetError("invalid username")
    return Path(f"client_{username}")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ClientAssetError(f"{_display_path(path)} not found")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ClientAssetError(f"{_display_path(path)} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ClientAssetError(f"{_display_path(path)} must contain a JSON object")
    return data


def _read_bytes(path: Path) -> bytes:
    if not path.exists():
        raise ClientAssetError(f"{_display_path(path)} not found")
    return path.read_bytes()


def _load_client_assets(
    username: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Return ``(config, client_cert, private_pem, ca_pubkey_pem)``."""
    client_dir = client_dir_for_user(username)
    config = _read_json(client_dir / "config.json")
    cert = _read_json(client_dir / "cert.json")
    ca_cert = _read_json(client_dir / "ca_cert.json")
    private_pem = _read_bytes(client_dir / "private.pem")

    configured_username = config.get("username")
    if configured_username is not None and configured_username != username:
        raise ClientAssetError(
            f"{_display_path(client_dir / 'config.json')} username mismatch"
        )

    ca_pubkey = ca_cert.get("public_key_pem")
    if not isinstance(ca_pubkey, str):
        raise ClientAssetError(
            f"{_display_path(client_dir / 'ca_cert.json')} missing public_key_pem"
        )

    return config, cert, private_pem, ca_pubkey.encode("ascii")


def login_session(username: str, password: bytes) -> dict[str, Any]:
    """Open a TCP connection and run the client handshake.

    Returns the frozen session-state dict from
    :func:`zerotrust.client.handshake.perform_client_handshake`. The
    password is consumed for this single call and not retained.

    Raises:
        ClientAssetError: missing / malformed local files.
        ConnectionRefusedError, TimeoutError, OSError: network issues.
        AuthError, CryptoError, ProtocolError: handshake / auth failures
            (the CLI collapses these to a generic ``AUTH_FAILED`` per
            AI.md §4.36).
    """
    client_dir = client_dir_for_user(username)
    config_path = client_dir / "config.json"
    config, client_cert, private_pem, ca_pubkey_pem = _load_client_assets(username)

    host = config.get("server_host")
    port = config.get("server_port")
    if not isinstance(host, str) or not host:
        raise ClientAssetError(f"{_display_path(config_path)} missing server_host")
    if not isinstance(port, int):
        raise ClientAssetError(f"{_display_path(config_path)} missing server_port")

    expected_server_subject = config.get("server_subject")
    if expected_server_subject is not None and not isinstance(
        expected_server_subject, str
    ):
        raise ClientAssetError(
            f"{_display_path(config_path)} server_subject must be a string"
        )

    with socket.create_connection(
        (host, port),
        timeout=DEFAULT_CONNECT_TIMEOUT_SECONDS,
    ) as sock:
        return perform_client_handshake(
            sock=sock,
            client_cert=client_cert,
            client_priv_pem=private_pem,
            client_password=password,
            ca_pubkey_pem=ca_pubkey_pem,
            expected_server_subject=expected_server_subject,
        )


__all__ = [
    "ClientAssetError",
    "client_dir_for_user",
    "login_session",
]
