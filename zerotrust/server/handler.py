"""Per-connection thread logic (Phase 2 — issues #5, #13; Phase 3 — #16, #17).

After the handshake completes, the handler dispatches on the encrypted
envelope's ``type`` field to the right verb. Phase 2 wires upload; Phase 3
wires list/download/revoke/ack.
"""

from __future__ import annotations

import socket


def serve_connection(sock: socket.socket, addr: tuple, server_state: dict) -> None:
    """Top-level per-connection routine. Stub at end of Phase 1."""
    raise NotImplementedError("server.handler.serve_connection — Phase 2 issue #5")
