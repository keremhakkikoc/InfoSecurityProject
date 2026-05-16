import base64
import hashlib
import json
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any

from zerotrust.ca.cert import verify_certificate
from zerotrust.common.exceptions import AuthError, ProtocolError
from zerotrust.common.origin import verify_origin_struct
from zerotrust.common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from zerotrust.server import replay, store
from zerotrust.server.handshake import perform_server_handshake

logger = logging.getLogger(__name__)

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
_DEMO_SERVER_PASSWORD = b"demo-password"


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ProtocolError(f"{path.as_posix()} must contain a JSON object")
    return data


def _server_password(server_state: dict[str, Any]) -> bytes:
    configured = server_state.get("server_password")
    if isinstance(configured, bytes):
        return configured
    if isinstance(configured, str):
        return configured.encode("utf-8")
    env_password = os.environ.get("ZEROTRUST_SERVER_PASSWORD")
    if env_password:
        return env_password.encode("utf-8")
    return _DEMO_SERVER_PASSWORD


def _load_server_assets(server_state: dict[str, Any]) -> tuple[dict, bytes, bytes, bytes]:
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


def _storage_dir(server_state: dict[str, Any]) -> Path:
    configured = server_state.get("storage_dir")
    if configured is not None:
        return Path(configured)
    return Path(server_state.get("db_path", "server/storage/metadata.db")).parent


def _pubkeys_dir(server_state: dict[str, Any]) -> Path:
    configured = server_state.get("pubkeys_dir")
    if configured is not None:
        return Path(configured)
    return _storage_dir(server_state) / "pubkeys"


def _files_dir(server_state: dict[str, Any]) -> Path:
    configured = server_state.get("files_dir")
    if configured is not None:
        return Path(configured)
    return _storage_dir(server_state) / "files"


def _send_error(sock, code: str) -> None:
    send_message(sock, make_envelope("ERROR", {"code": code}))


def _valid_username(username: Any) -> bool:
    return isinstance(username, str) and _USERNAME_RE.fullmatch(username) is not None


def _load_verified_pubkey_cert(
    username: str,
    server_state: dict[str, Any],
    ca_pubkey_pem: bytes,
) -> dict[str, Any] | None:
    if not _valid_username(username):
        return None
    path = _pubkeys_dir(server_state) / f"{username}.json"
    if not path.is_file():
        return None
    try:
        cert = _read_json(path)
    except (OSError, json.JSONDecodeError, ProtocolError):
        return None
    if not verify_certificate(cert, ca_pubkey_pem, expected_subject=username):
        return None
    return cert


def _handle_get_pubkey(sock, payload: dict[str, Any], server_state: dict[str, Any],
                       ca_pubkey_pem: bytes) -> None:
    cert = _load_verified_pubkey_cert(
        payload.get("username"),
        server_state,
        ca_pubkey_pem,
    )
    if cert is None:
        _send_error(sock, "NOT_FOUND")
        return
    send_message(sock, make_envelope("PUBKEY_RESPONSE", {"cert": cert}))


def _decode_b64_field(payload: dict[str, Any], name: str) -> bytes:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ProtocolError(f"missing {name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError(f"{name} is not valid base64") from exc


def _aad(file_id: str, sender: str, recipient: str) -> bytes:
    return f"{file_id}|{sender}|{recipient}".encode()


def _handle_upload_request(sock, envelope: dict[str, Any], db_conn,
                           session: dict[str, Any], server_state: dict[str, Any],
                           ca_pubkey_pem: bytes) -> None:
    try:
        envelope_nonce = base64.b64decode(envelope["nonce"], validate=True)
    except Exception:  # noqa: BLE001
        _send_error(sock, "MALFORMED")
        return
    if not replay.check_and_record(db_conn, envelope_nonce, envelope["timestamp"]):
        _send_error(sock, "STALE")
        return

    sender = session["peer_subject"]
    if not verify_certificate(session["peer_cert"], ca_pubkey_pem, expected_subject=sender):
        _send_error(sock, "AUTH_FAILED")
        return

    payload = envelope["payload"]
    try:
        file_id = payload["file_id"]
        recipient = payload["recipient"]
        timestamp = payload["timestamp"]
        expiration = payload["expiration"]
        if not isinstance(file_id, str) or str(uuid.UUID(file_id)) != file_id:
            raise ProtocolError("invalid file_id")
        if not _valid_username(recipient):
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
        logger.warning("origin verify failed for sender=%s file_id=%s", sender, file_id)
        _send_error(sock, "AUTH_FAILED")
        return

    if _load_verified_pubkey_cert(recipient, server_state, ca_pubkey_pem) is None:
        _send_error(sock, "NOT_FOUND")
        return

    files_dir = _files_dir(server_state)
    files_dir.mkdir(parents=True, exist_ok=True)
    final_path = files_dir / f"{file_id}.bin"
    tmp_path = files_dir / f"{file_id}.bin.tmp"
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
        logger.exception("upload write failed for sender=%s file_id=%s", sender, file_id)
        _send_error(sock, "INTERNAL_ERROR")
        return

    send_message(sock, make_envelope("UPLOAD_ACK", {
        "file_id": file_id,
        "expiration": expiration,
    }))
    logger.info("upload accepted file=%s sender=%s recipient=%s",
                file_id, sender, recipient)


def serve_connection(sock, addr, server_state):
    """
    Handles a single client connection. This function runs in a dedicated worker thread.
    
    Args:
        sock (socket.socket): The client socket.
        addr (tuple): The client address (ip, port).
        server_state (dict): Shared server configuration and state.
    """
    logger.info(f"[*] Yeni baglanti kabul edildi: {addr}")
    
    # KURAL: Thread'ler arası SQLite bağlantısı paylaşmak YASAKTIR.
    # Her thread, veritabanı işlemlerini gerçekleştirmek için kendi sqlite3.Connection 
    # nesnesini açmalıdır. Aksi halde thread-safety sorunları ve "database is locked" 
    # hataları alınır. SQLite, varsayılan olarak multi-threading ortamlarda aynı 
    # bağlantının paylaşılmasını engeller.
    # db_conn = sqlite3.connect(db_path)
    # try:
    #     ... veritabanı işlemleri ...
    # finally:
    #     db_conn.close()
    
    db_conn = None
    try:
        server_cert, private_pem, password, ca_pubkey_pem = _load_server_assets(server_state)
        db_conn = store.open_connection(server_state.get("db_path", "server/storage/metadata.db"))
        store.init_schema(db_conn)
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
                break
            if envelope["type"] == "GET_PUBKEY":
                _handle_get_pubkey(sock, envelope["payload"], server_state, ca_pubkey_pem)
            elif envelope["type"] == "UPLOAD_REQUEST":
                _handle_upload_request(
                    sock,
                    envelope,
                    db_conn,
                    session,
                    server_state,
                    ca_pubkey_pem,
                )
            else:
                _send_error(sock, "MALFORMED")

    except (AuthError, ProtocolError, OSError) as e:
        # KURAL: En dışı try/except Exception: bloğu ile sarılmalı ki, 
        # bozuk bir istemci (bad client) sunucuyu çökertmesin.
        logger.error(f"[-] {addr} istemcisinde hata: {e}")
    except Exception as e:
        logger.exception(f"[-] {addr} istemcisinde beklenmeyen hata: {e}")
    finally:
        if db_conn is not None:
            db_conn.close()
        try:
            sock.close()
            logger.info(f"[*] Baglanti kapatildi: {addr}")
        except Exception as e:
            logger.error(f"[-] {addr} baglantisi kapatilirken hata: {e}")
