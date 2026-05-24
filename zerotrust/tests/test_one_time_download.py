import base64
import time
import pytest
import sqlite3

from zerotrust.common.canonical import canonical_json
from zerotrust.common.crypto_primitives import rsa_sign
from zerotrust.common.protocol import make_envelope, recv_message, send_message, validate_envelope

# We can reuse the environment from test_revocation
from .test_revocation import _build_env, _running_server, _session_socket, _upload_one, _row_status, _b64, BOB_PASSWORD, MALLORY_PASSWORD, _Env

@pytest.fixture
def env(tmp_path):
    return _build_env(tmp_path)

def _send_ack(env, session, file_id, signer_priv, signer_pw):
    ts = int(time.time())
    canonical = canonical_json(
        {"file_id": file_id, "status": "received", "timestamp": ts}
    )
    sig = rsa_sign(signer_priv, signer_pw, canonical)
    payload = {
        "file_id": file_id,
        "timestamp": ts,
        "signature": _b64(sig),
    }
    envelope = make_envelope("DOWNLOAD_ACK", payload)
    send_message(session["sock"], envelope)
    return validate_envelope(recv_message(session["sock"])), envelope

def test_happy_one_time_download(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        assert _row_status(env, file_id) == "pending"

        # Bob downloads
        with _session_socket(env, port, user="bob") as session:
            send_message(session["sock"], make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
            reply = validate_envelope(recv_message(session["sock"]))
            assert reply["type"] == "DOWNLOAD_RESPONSE"
        
        # Row is STILL pending!
        assert _row_status(env, file_id) == "pending"
        
        # Bob ACKs
        with _session_socket(env, port, user="bob") as session:
            reply, _ = _send_ack(env, session, file_id, env.bob_priv, BOB_PASSWORD)
            assert reply["type"] == "ACK_OK"
            assert _row_status(env, file_id) == "downloaded"
            
            # Check acks table
            conn = sqlite3.connect(str(env.db_path))
            ack_row = conn.execute("SELECT * FROM acks WHERE file_id = ?", (file_id,)).fetchone()
            conn.close()
            assert ack_row is not None
        
        # Bob tries to download again
        with _session_socket(env, port, user="bob") as session:
            send_message(session["sock"], make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
            reply = validate_envelope(recv_message(session["sock"]))
            assert reply["type"] == "ERROR"
            assert reply["payload"]["code"] == "ALREADY_DOWNLOADED"

def test_retry_path_download(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        
        with _session_socket(env, port, user="bob") as session1:
            send_message(session1["sock"], make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
            reply1 = validate_envelope(recv_message(session1["sock"]))
            assert reply1["type"] == "DOWNLOAD_RESPONSE"
            
        with _session_socket(env, port, user="bob") as session2:
            send_message(session2["sock"], make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
            reply2 = validate_envelope(recv_message(session2["sock"]))
            assert reply2["type"] == "DOWNLOAD_RESPONSE"
            
            # ACK from session2
            reply_ack, _ = _send_ack(env, session2, file_id, env.bob_priv, BOB_PASSWORD)
            assert reply_ack["type"] == "ACK_OK"
            
        with _session_socket(env, port, user="bob") as session3:
            send_message(session3["sock"], make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
            reply3 = validate_envelope(recv_message(session3["sock"]))
            assert reply3["type"] == "ERROR"
            assert reply3["payload"]["code"] == "ALREADY_DOWNLOADED"

def test_forged_ack(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        
        with _session_socket(env, port, user="bob") as session:
            # Bob sends ACK but signs with Mallory's key
            reply, _ = _send_ack(env, session, file_id, env.mallory_priv, MALLORY_PASSWORD)
            assert reply["type"] == "ERROR"
            assert reply["payload"]["code"] == "AUTH_FAILED"
            assert _row_status(env, file_id) == "pending"

def test_replay_ack(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        
        with _session_socket(env, port, user="bob") as session:
            reply1, envelope = _send_ack(env, session, file_id, env.bob_priv, BOB_PASSWORD)
            assert reply1["type"] == "ACK_OK"
            
            # replay
            send_message(session["sock"], envelope)
            reply2 = validate_envelope(recv_message(session["sock"]))
            assert reply2["type"] == "ERROR"
            assert reply2["payload"]["code"] in ("STALE", "REPLAY")
