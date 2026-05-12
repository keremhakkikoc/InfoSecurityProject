"""Server entry point — Phase 2 issue #5.

Starts a ``ThreadingTCPServer``, loads server keys + cert, opens the
metadata DB, and dispatches accepted sockets to ``handler.serve_connection``.
"""

from __future__ import annotations


def main() -> int:
    raise NotImplementedError("server.main — Phase 2 issue #5")


if __name__ == "__main__":
    raise SystemExit(main())
