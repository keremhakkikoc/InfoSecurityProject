## Goal
Make `python -m zerotrust.server.main` accept multiple concurrent clients without one slow client blocking others.

## Why this matters
The grading demo requires Alice and Bob (and possibly the grader) to be connected at the same time. A single-threaded `accept` loop would serialise them. ARCHITECTURE.md §6 freezes the concurrency model: one thread per accepted connection.

## Dependencies
- **Blocks:** every other M2 issue at runtime (no one can actually exercise their code until the server boots).
- **Blocked by:** none. You can start day 1.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/main.py` | Replace `NotImplementedError` with a real entry point. |
| `zerotrust/server/handler.py` | Provide a `serve_connection(sock, addr, server_state)` stub that just logs and closes for now — #13 fills the body later. |
| `zerotrust/tests/test_server_boot.py` | **NEW** — boot the server on an ephemeral port, connect two clients in parallel, assert both get a banner / accept. |

## Frozen helpers you will use
```python
from zerotrust.common.logger import get_logger
log = get_logger("server.main", log_file="server/logs/audit.log")
```

## Implementation steps
1. Parse a tiny config: `--host 127.0.0.1`, `--port 5050`, `--db server/storage/metadata.db`, `--ca-cert ca_data/ca_cert.json`. Use `argparse`.
2. Load the server's cert + private key (PEM). Refuse to start if anything is missing.
3. Use `socketserver.ThreadingTCPServer` OR `threading.Thread` per `socket.accept()`. **Daemon threads.**
4. Each connection thread MUST open its **own** `sqlite3.Connection`. Do NOT share a connection — see ARCHITECTURE.md §5/§6.
5. Wrap the per-connection handler in a top-level `try/except Exception` so one bad client never kills the server. Log + close the socket.
6. Handle `SIGINT` / `KeyboardInterrupt` to shut down the listener cleanly.

## Acceptance criteria
- [ ] `python -m zerotrust.server.main --port 5050` prints `INFO ... listening on 127.0.0.1:5050` and stays up.
- [ ] Two concurrent clients can connect; the slow one does not block the fast one (test must prove this — use `threading.Event` to sequence reads).
- [ ] A client that crashes mid-message does not crash the server (test forces a `conn.close()` mid-read).
- [ ] `Ctrl+C` shuts the server down gracefully — no `Thread-N` zombie warnings.
- [ ] `make test` passes including the new `test_server_boot.py`.

## Required tests
* **Happy path:** spin up `ThreadingTCPServer` on `127.0.0.1:0` (ephemeral), open two `socket.create_connection`s, both succeed within 500 ms.
* **Negative path 1:** one client `close()`s mid-handshake → server logs a warning, second client unaffected.
* **Negative path 2:** server thread raises inside `serve_connection` → server still alive on next accept.

## Pitfalls
- Do NOT use `select` or `asyncio` — ARCHITECTURE.md §6 froze the threading model.
- Do NOT share the SQLite connection between threads — `sqlite3` is not thread-safe unless you do.
- Do NOT use `signal.signal(SIGINT, ...)` from a worker thread — only the main thread can install signal handlers.
- The test must use an **ephemeral port (`0`)** so CI doesn't fight with whatever's listening on 5050.

## References
- ARCHITECTURE.md §6 (Concurrency Model)
- ARCHITECTURE.md §10 (Module Layout)
