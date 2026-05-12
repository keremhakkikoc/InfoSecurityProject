"""Client-side handshake (Phase 2 — issues #7, #8, #9).

Mirrors ``server/handshake.py``: client opens the socket, performs HELLO
exchange, sends RSA-OAEP wrapped pre-master, signs the transcript hash, and
returns the same session-state shape.
"""

from __future__ import annotations

import socket
from typing import Any


def perform_client_handshake(sock: socket.socket,
                             client_cert: dict,
                             client_priv_pem: bytes,
                             client_password: bytes,
                             ca_pubkey_pem: bytes,
                             expected_server_subject: str | None = None) -> dict[str, Any]:
    """Run the handshake; return ``{"peer_subject", "peer_cert", "c2s_key",
    "s2c_key", "transcript_hash"}``."""
    raise NotImplementedError(
        "client.handshake.perform_client_handshake — Phase 2 issue #8"
    )
