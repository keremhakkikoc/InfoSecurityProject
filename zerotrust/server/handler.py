"""Per-connection thread logic.

After the handshake (#8) completes, the handler dispatches on the
envelope's ``type`` field. This file currently wires:
  - GET_PUBKEY  (#21, this PR)
later additions: UPLOAD_REQUEST (#13), LIST/DOWNLOAD/REVOKE (M3).
"""

from __future__ import annotations

import logging
import socket

from zerotrust.ca.cert import verify_certificate
from zerotrust.common.exceptions import ProtocolError
from zerotrust.common.logger import fingerprint
from zerotrust.common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from zerotrust.server.storage_layout import (
    USERNAME_REGEX,
    load_pubkey_cert,
)

logger = logging.getLogger("server.handler")


def _send_error(sock: socket.socket, code: str) -> None:
    """Best-effort generic error to the peer. Per AI.md §4.36 we never
    leak the real reason — only the generic code goes on the wire."""
    try:
        send_message(sock, make_envelope("ERROR", {"code": code}))
    except OSError:
        pass


def _handle_get_pubkey(sock: socket.socket, session: dict, payload: dict) -> None:
    """Serve a GET_PUBKEY request.

    Steps:
      1. Validate the username against ``USERNAME_REGEX`` — this is the
         path-traversal boundary. Anything not matching is treated as
         NOT_FOUND, never a filesystem error.
      2. Load ``<storage_base>/pubkeys/<username>.json`` if it exists.
      3. Defence-in-depth: server re-verifies the cert against its own
         CA trust anchor before returning. A planted-cert attack on the
         filesystem still produces NOT_FOUND, not a forged peer cert.
      4. Reply with PUBKEY_RESPONSE carrying the cert dict.
    """
    username = payload.get("username", "")
    if not isinstance(username, str) or not USERNAME_REGEX.match(username):
        logger.warning("get_pubkey: rejected invalid username")
        _send_error(sock, "NOT_FOUND")
        return

    storage_base = session.get("server_state", {}).get(
        "storage_base", "server/storage"
    )
    ca_pubkey_pem = session.get("server_state", {}).get("ca_pubkey_pem")
    if not ca_pubkey_pem:
        logger.error("get_pubkey: server has no CA trust anchor configured")
        _send_error(sock, "NOT_FOUND")
        return

    cert = load_pubkey_cert(storage_base, username)
    if cert is None:
        logger.info("get_pubkey: %s not found", username)
        _send_error(sock, "NOT_FOUND")
        return

    # Defence-in-depth: the file on disk might have been planted. Verify
    # against the CA trust anchor AND require subject == username.
    if not verify_certificate(cert, ca_pubkey_pem, expected_subject=username):
        logger.warning(
            "get_pubkey: stored cert for %s failed CA verification (fp=%s)",
            username, fingerprint(cert.get("public_key_pem", "").encode()),
        )
        _send_error(sock, "NOT_FOUND")
        return

    send_message(sock, make_envelope("PUBKEY_RESPONSE", {"cert": cert}))
    logger.info("get_pubkey: served cert for %s", username)


def _dispatch(sock: socket.socket, session: dict, envelope: dict) -> None:
    """Route a validated envelope to the right handler.

    Unknown / unsupported types get a generic MALFORMED back. Each handler
    is responsible for its own error reporting; an unhandled exception
    bubbles up to ``serve_connection`` which logs and closes.
    """
    msg_type = envelope["type"]
    payload = envelope["payload"]

    if msg_type == "GET_PUBKEY":
        _handle_get_pubkey(sock, session, payload)
    else:
        # Other message types land in later PRs (#13 upload, M3 download).
        logger.warning("unsupported message type: %s", msg_type)
        _send_error(sock, "MALFORMED")


def serve_connection(sock: socket.socket, addr: tuple, server_state: dict) -> None:
    """Top-level per-connection routine, run in its own thread.

    For #21 we don't yet exercise the full handshake before dispatch —
    that integration lands when #13 wires the upload path. For now,
    handlers that don't require authenticated session state (like
    GET_PUBKEY) can be served directly. Session-bearing handlers will
    add the handshake call at the top once #13 lands.
    """
    logger.info("[+] connection from %s", addr)
    session: dict = {
        "server_state": server_state,
        "peer_subject": None,
        "peer_cert": None,
    }
    try:
        envelope = validate_envelope(recv_message(sock))
        _dispatch(sock, session, envelope)
    except ProtocolError as exc:
        logger.warning("[%s] protocol error: %s", addr, exc)
        _send_error(sock, "MALFORMED")
    except OSError as exc:
        # Client disconnected, broken pipe, etc. — log and move on, do
        # NOT crash the server thread.
        logger.warning("[%s] socket error: %s", addr, exc)
    except Exception as exc:  # noqa: BLE001 — last-resort isolation
        logger.exception("[%s] unexpected handler error: %s", addr, exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
        logger.info("[-] closed %s", addr)
