"""Per-connection server handler.

Runs on a dedicated worker thread (``ThreadingTCPServer``). The flow is:

    perform_server_handshake → loop over envelopes:
        GET_PUBKEY        → lookup in CA-verified pubkey directory
        UPLOAD_REQUEST    → replay-check, verify origin sig, atomic write,
                            insert metadata row, send UPLOAD_ACK

This module establishes the verified end-to-end path for issue #19. The
*exhaustive* failure-mode coverage (tampered ciphertext, forged signature,
stale timestamp, replayed nonce, unknown recipient, atomic-write crash)
belongs to issue #20 (#13 in the milestone). The handler here already runs
each check fail-closed; #20 will add the dedicated regression tests.

SQLite rule (AI.md §5): each thread opens its own ``sqlite3.Connection``;
the connection is never cached at module scope.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from ..ca.cert import verify_certificate
from ..common.exceptions import AuthError, ProtocolError
from ..common.origin import verify_origin_struct
from ..common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from . import replay, store
from .handshake import perform_server_handshake
from .storage_layout import (
    file_blob_path_for,
    pubkey_path_for,
    valid_username,
)

logger = logging.getLogger(__name__)

_DEMO_SERVER_PASSWORD = b"demo-password"


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ProtocolError(f"{path.as_posix()} must contain a JSON object")
    return data


def _server_password(server_state: dict[str, Any]) -> bytes:
    """Resolve the server's private-key password.

    Priority: explicit ``server_state['server_password']`` (used by tests) >
    ``ZEROTRUST_SERVER_PASSWORD`` env var > documented demo password.
    """
    configured = server_state.get("server_password")
    if isinstance(configured, bytes):
        return configured
    if isinstance(configured, str):
        return configured.encode("utf-8")
    env_password = os.environ.get("ZEROTRUST_SERVER_PASSWORD")
    if env_password:
        return env_password.encode("utf-8")
    return _DEMO_SERVER_PASSWORD


def _load_server_assets(
    server_state: dict[str, Any],
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    """Return ``(server_cert, priv_pem, password, ca_pubkey_pem)``.

    Pre-loaded values in ``server_state`` take precedence; this lets tests
    plug in already-built keypairs without writing them to disk.
    """
    server_cert = server_state.get("server_cert")
    if not isinstance(server_cert, dict):
        server_cert = _read_json(Path(server_state["cert_path"]))

    private_pem = server_state.get("server_priv_pem")
    if not isinstance(private_pem, bytes):
        private_pem = Path(server_state["key_path"]).read_bytes()

    ca_pubkey_pem = server_state.get("ca_pubkey_pem")
    if not isinstance(ca_pubkey_pem, bytes):
        ca_cert = _read_json(Path(server_state["ca_cert_path"]))
        ca_pubkey = ca_cert.get("public_key_pem")
        if not isinstance(ca_pubkey, str):
            raise ProtocolError("CA cert missing public_key_pem")
        ca_pubkey_pem = ca_pubkey.encode("ascii")

    return server_cert, private_pem, _server_password(server_state), ca_pubkey_pem


def _send_error(sock, code: str) -> None:
    """Generic error to the peer (ARCHITECTURE.md §7.9 — opaque codes)."""
    send_message(sock, make_envelope("ERROR", {"code": code}))


def _load_verified_pubkey_cert(
    username: Any,
    server_state: dict[str, Any],
    ca_pubkey_pem: bytes,
) -> dict[str, Any] | None:
    """Return ``username``'s CA-verified cert dict or ``None``.

    Returns ``None`` for any reason — invalid username, missing file,
    unreadable file, malformed JSON, signature failure — so the caller
    can map every miss to a single opaque ``NOT_FOUND`` per AI.md §4.36
    without leaking which check tripped.
    """
    path = pubkey_path_for(server_state, username)
    if path is None or not path.is_file():
        return None
    try:
        cert = _read_json(path)
    except (OSError, json.JSONDecodeError, ProtocolError):
        return None
    if not verify_certificate(cert, ca_pubkey_pem, expected_subject=username):
        return None
    return cert


# ---------------------------------------------------------------------------
# GET_PUBKEY
# ---------------------------------------------------------------------------

def _handle_get_pubkey(
    sock,
    payload: dict[str, Any],
    server_state: dict[str, Any],
    ca_pubkey_pem: bytes,
) -> None:
    cert = _load_verified_pubkey_cert(
        payload.get("username"),
        server_state,
        ca_pubkey_pem,
    )
    if cert is None:
        _send_error(sock, "NOT_FOUND")
        return
    send_message(sock, make_envelope("PUBKEY_RESPONSE", {"cert": cert}))


# ---------------------------------------------------------------------------
# LIST_PENDING
# ---------------------------------------------------------------------------

def _handle_list_pending(
    sock,
    db_conn,
    session: dict[str, Any],
    server_state: dict[str, Any],
) -> None:
    """Return metadata-only pending rows for the authenticated recipient."""
    recipient = session["peer_subject"]
    rows = store.list_pending_for(db_conn, recipient)
    files = []
    for row in rows:
        blob_path = file_blob_path_for(server_state, row["file_id"])
        try:
            ciphertext_size = blob_path.stat().st_size
        except OSError:
            ciphertext_size = None
        files.append(
            {
                "file_id": row["file_id"],
                "sender_id": row["sender_id"],
                "upload_timestamp": row["upload_timestamp"],
                "expiration": row["expiration"],
                "ciphertext_size": ciphertext_size,
            }
        )
    send_message(sock, make_envelope("PENDING_LIST", {"files": files}))


# ---------------------------------------------------------------------------
# UPLOAD_REQUEST
# ---------------------------------------------------------------------------

def _decode_b64_field(payload: dict[str, Any], name: str) -> bytes:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ProtocolError(f"missing {name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError(f"{name} is not valid base64") from exc


def _aad(file_id: str, sender: str, recipient: str) -> bytes:
    """Mirror :func:`zerotrust.common.file_crypto._file_aad`."""
    return f"{file_id}|{sender}|{recipient}".encode()


def _handle_upload_request(
    sock,
    envelope: dict[str, Any],
    db_conn,
    session: dict[str, Any],
    server_state: dict[str, Any],
    ca_pubkey_pem: bytes,
) -> None:
    # 1. Replay protection (cheap — do FIRST to avoid expensive DoS via crypto).
    try:
        envelope_nonce = base64.b64decode(envelope["nonce"], validate=True)
    except Exception:  # noqa: BLE001
        _send_error(sock, "MALFORMED")
        return
    if not replay.check_and_record(db_conn, envelope_nonce, envelope["timestamp"]):
        _send_error(sock, "STALE")
        return

    # 2. Sender identity comes from the handshake, NOT from any payload field.
    sender = session["peer_subject"]
    if not verify_certificate(session["peer_cert"], ca_pubkey_pem, expected_subject=sender):
        _send_error(sock, "AUTH_FAILED")
        return

    # 3. Decode + sanity-check payload fields.
    payload = envelope["payload"]
    try:
        file_id = payload["file_id"]
        recipient = payload["recipient"]
        timestamp = payload["timestamp"]
        expiration = payload["expiration"]
        if not isinstance(file_id, str) or str(uuid.UUID(file_id)) != file_id:
            raise ProtocolError("invalid file_id")
        if not valid_username(recipient):
            raise ProtocolError("invalid recipient")
        if not isinstance(timestamp, int) or not isinstance(expiration, int):
            raise ProtocolError("timestamp/expiration must be int")

        ciphertext = _decode_b64_field(payload, "ciphertext")
        aes_nonce = _decode_b64_field(payload, "nonce")
        wrapped_key = _decode_b64_field(payload, "wrapped_key")
        signature = _decode_b64_field(payload, "signature")
    except (KeyError, ValueError, ProtocolError):
        _send_error(sock, "MALFORMED")
        return

    # 4. Re-hash ciphertext and wrapped key, then verify origin signature.
    #    Tampering with any envelope field — sender, recipient, file_id,
    #    timestamp, expiration, or the bytes themselves — breaks this check.
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    if not verify_origin_struct(
        session["peer_cert"],
        signature,
        sender=sender,
        recipient=recipient,
        file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp,
        expiration=expiration,
    ):
        logger.warning("origin verify failed sender=%s file_id=%s", sender, file_id)
        _send_error(sock, "AUTH_FAILED")
        return

    # 5. Recipient must exist in the pubkey directory.
    if _load_verified_pubkey_cert(recipient, server_state, ca_pubkey_pem) is None:
        _send_error(sock, "NOT_FOUND")
        return

    # 6. Atomic write: *.tmp → os.replace. A crash mid-write leaves no
    #    half-files in the final directory.
    final_path = file_blob_path_for(server_state, file_id)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = final_path.parent / f"{final_path.name}.tmp"
    try:
        with tmp_path.open("wb") as f:
            f.write(ciphertext)
        os.replace(tmp_path, final_path)
        store.insert_file(
            db_conn,
            {
                "file_id": file_id,
                "sender_id": sender,
                "recipient_id": recipient,
                "upload_timestamp": timestamp,
                "expiration": expiration,
                "status": "pending",
                "ciphertext_path": f"{file_id}.bin",
                "ciphertext_sha256": ciphertext_sha256,
                "wrapped_key": wrapped_key,
                "aes_nonce": aes_nonce,
                "aes_aad": _aad(file_id, sender, recipient),
                "sender_signature": signature,
                "sender_cert_json": json.dumps(session["peer_cert"], sort_keys=True),
            },
        )
    except OSError:
        logger.exception("upload write failed sender=%s file_id=%s", sender, file_id)
        _send_error(sock, "INTERNAL_ERROR")
        return

    send_message(sock, make_envelope("UPLOAD_ACK", {
        "file_id": file_id,
        "expiration": expiration,
    }))
    logger.info(
        "upload accepted file=%s sender=%s recipient=%s",
        file_id, sender, recipient,
    )


# ---------------------------------------------------------------------------
# DOWNLOAD_REQUEST
# ---------------------------------------------------------------------------


def _handle_download_request(
    sock,
    envelope: dict[str, Any],
    db_conn,
    session: dict[str, Any],
    server_state: dict[str, Any],
) -> None:
    payload = envelope["payload"]
    try:
        file_id = payload["file_id"]
    except KeyError:
        _send_error(sock, "MALFORMED")
        return

    # Erişim Kontrolü (Access Control)
    file_record = store.get_file(db_conn, file_id)
    if not file_record:
        _send_error(sock, "NOT_FOUND")
        return

    # KURAL: Eğer veritabanındaki recipient_id, oturumdaki session["peer_subject"] 
    # ile EŞLEŞMİYORSA anında AUTH_FAILED dön (Yetkisiz erişim engeli).
    if file_record["recipient_id"] != session["peer_subject"]:
        logger.warning("Unauthorized download attempt for %s by %s", file_id, session["peer_subject"])
        _send_error(sock, "AUTH_FAILED")
        return

    if file_record["status"] != "pending":
        _send_error(sock, "NOT_FOUND")
        return

    if file_record["expiration"] < int(time.time()):
        _send_error(sock, "EXPIRED")
        return

    # Diskteki ciphertext'i oku
    final_path = file_blob_path_for(server_state, file_id)
    if not final_path.is_file():
        logger.error("File %s metadata exists but blob is missing!", file_id)
        _send_error(sock, "INTERNAL_ERROR")
        return

    try:
        ciphertext = final_path.read_bytes()
    except OSError:
        logger.exception("Failed to read blob for %s", file_id)
        _send_error(sock, "INTERNAL_ERROR")
        return

    response_payload = {
        "file_id": file_id,
        "sender_id": file_record["sender_id"],
        "timestamp": file_record["upload_timestamp"],
        "expiration": file_record["expiration"],
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "wrapped_key": base64.b64encode(file_record["wrapped_key"]).decode("ascii"),
        "aes_nonce": base64.b64encode(file_record["aes_nonce"]).decode("ascii"),
        "aes_aad": base64.b64encode(file_record["aes_aad"]).decode("ascii"),
        "sender_signature": base64.b64encode(file_record["sender_signature"]).decode("ascii"),
        "sender_cert_json": file_record["sender_cert_json"],
    }

    send_message(sock, make_envelope("DOWNLOAD_RESPONSE", response_payload))
    logger.info("download fulfilled file=%s recipient=%s", file_id, session["peer_subject"])

# ---------------------------------------------------------------------------
# Connection driver
# ---------------------------------------------------------------------------

def serve_connection(sock, addr, server_state):
    """Handle one client connection; runs on a dedicated worker thread.

    Each thread opens its own ``sqlite3.Connection`` (AI.md §5 — no
    sharing) and closes it in ``finally`` so a bad client never leaks a
    DB handle.
    """
    logger.info("[*] connection accepted: %s", addr)

    db_conn = None
    try:
        server_cert, private_pem, password, ca_pubkey_pem = _load_server_assets(
            server_state
        )
        db_conn = store.open_connection(
            server_state.get("db_path", "server/storage/metadata.db")
        )
        store.init_schema(db_conn)
        replay.init_schema(db_conn)

        session = perform_server_handshake(
            sock=sock,
            server_cert=server_cert,
            server_priv_pem=private_pem,
            server_password=password,
            ca_pubkey_pem=ca_pubkey_pem,
        )

        while True:
            try:
                envelope = validate_envelope(recv_message(sock))
            except ProtocolError:
                # Client closed or sent garbage — end the loop cleanly.
                break

            msg_type = envelope["type"]
            if msg_type == "GET_PUBKEY":
                _handle_get_pubkey(
                    sock, envelope["payload"], server_state, ca_pubkey_pem
                )
            elif msg_type == "LIST_PENDING":
                _handle_list_pending(sock, db_conn, session, server_state)
            elif msg_type == "UPLOAD_REQUEST":
                _handle_upload_request(
                    sock,
                    envelope,
                    db_conn,
                    session,
                    server_state,
                    ca_pubkey_pem,
                )
            elif msg_type == "DOWNLOAD_REQUEST":
                _handle_download_request(
                    sock,
                    envelope,
                    db_conn,
                    session,
                    server_state,
                )
            else:
                _send_error(sock, "MALFORMED")

    except (AuthError, ProtocolError, OSError) as exc:
        # Expected error classes — log at info, NOT exception (no stack trace).
        logger.info("[-] %s: %s", addr, exc)
    except Exception:  # noqa: BLE001
        # Unexpected — log with traceback so we can debug, but DO NOT
        # crash the worker thread (a bad client must not take the server down).
        logger.exception("[-] %s: unexpected handler error", addr)
    finally:
        if db_conn is not None:
            try:
                db_conn.close()
            except sqlite3.Error:
                pass
        try:
            sock.close()
        except OSError:
            pass
        logger.info("[*] connection closed: %s", addr)
