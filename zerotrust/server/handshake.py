"""Server-side handshake (Phase 2 — issues #6, #7, #8).

Implements the flow in ARCHITECTURE.md §7.4 and the HKDF derivation in §7.5.
This module is a stub at end-of-Phase-1; Phase 2 issues fill the bodies.
"""

from __future__ import annotations

import socket
from typing import Any


def perform_server_handshake(sock: socket.socket,
                             server_cert: dict,
                             server_priv_pem: bytes,
                             server_password: bytes,
                             ca_pubkey_pem: bytes) -> dict[str, Any]:
    """Run the handshake and return the negotiated session state.

    Expected return shape (frozen for Phase 2 callers):

        {
            "peer_subject": str,          # verified subject from peer cert
            "peer_cert": dict,            # the full verified peer cert
            "c2s_key": bytes,             # 32 bytes
            "s2c_key": bytes,             # 32 bytes
            "transcript_hash": bytes,     # SHA-256 binding §7.4
        }
    """
    raise NotImplementedError(
        "server.handshake.perform_server_handshake — Phase 2 issue #8"
    )
