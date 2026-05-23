## Goal
Background daemon thread inside the server that wakes every 60 seconds and does two janitorial things:
1. Deletes rows from `seen_nonces` whose `seen_at < now() - 300` seconds (5 min retention).
2. Updates `files` rows where `expiration <= now() AND status='pending'` to `status='expired'`.

## Why this matters
The 30-second envelope replay window is only safe if `seen_nonces` stays bounded — without cleanup, every envelope nonce we've ever seen would accumulate, making the table unbounded. And `'expired'` rows must be marked actively, not just inferred from a stale `expiration`, so the audit log records the transition.

## Dependencies
- **Blocked by:** `replay.purge_old_nonces` (M1), `store.mark_status` (#14).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/main.py` | Spawn the cleanup thread before `serve_forever()`. Daemon = True so it dies with the server. |
| `zerotrust/server/cleanup.py` | **NEW** — `def run_cleanup_loop(db_path, *, interval=60, stop_event=None)`. Opens its own SQLite connection. |
| `zerotrust/tests/test_cleanup.py` | **NEW** — fast-forward clock, assert rows transition. |

## Implementation steps
```python
# zerotrust/server/cleanup.py
import threading, time, sqlite3, logging
from . import replay, store

log = logging.getLogger(__name__)

def run_cleanup_loop(db_path, *, interval=60, stop_event=None):
    stop = stop_event or threading.Event()
    conn = sqlite3.connect(db_path)              # OWN thread, OWN connection
    try:
        while not stop.is_set():
            try:
                nonce_deleted = replay.purge_old_nonces(conn)
                expired_marked = _expire_pending(conn)
                if nonce_deleted or expired_marked:
                    log.info("cleanup: nonces=%d expired=%d", nonce_deleted, expired_marked)
            except Exception:
                log.exception("cleanup loop iteration failed")
            stop.wait(timeout=interval)
    finally:
        conn.close()

def _expire_pending(conn):
    now = int(time.time())
    with conn:
        cur = conn.execute(
            "UPDATE files SET status='expired' "
            "WHERE status='pending' AND expiration <= ?",
            (now,),
        )
        return cur.rowcount
```

In `main.py`:
```python
stop_event = threading.Event()
t = threading.Thread(target=run_cleanup_loop, args=(db_path,),
                     kwargs={"stop_event": stop_event}, daemon=True)
t.start()
try:
    server.serve_forever()
finally:
    stop_event.set()
    t.join(timeout=5.0)
```

## Acceptance criteria
- [ ] Cleanup thread starts with the server, logs `INFO cleanup: ...` on each non-trivial iteration.
- [ ] `seen_nonces` rows older than 5 minutes are deleted within one cleanup tick.
- [ ] `files` rows with `expiration <= now() AND status='pending'` flip to `'expired'` within one tick.
- [ ] Already-expired (`status='expired'`) rows are NOT re-touched (no churn).
- [ ] Server shutdown waits for the cleanup thread to finish current iteration (≤ 5s).
- [ ] An exception in one iteration does NOT kill the thread; next tick still runs.

## Required tests
- Insert nonce with `seen_at = now() - 600` → run one iteration → row gone.
- Insert nonce with `seen_at = now() - 60` → run iteration → row still present.
- Insert file row `expiration = now() - 1, status='pending'` → run iteration → status flips to `'expired'`.
- Insert file row `expiration = now() + 3600, status='pending'` → run iteration → status stays `'pending'`.
- Idempotent: run two iterations back-to-back on an already-cleaned DB → no errors, no spurious INFO log lines.
- Resilience: monkeypatch `_expire_pending` to raise once → cleanup logs the exception but continues; next iteration works.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** share the cleanup thread's connection with request handlers. AI.md §5: each thread opens its own `sqlite3.Connection`.
- ❌ **DO NOT** call `time.sleep(interval)` — use `stop_event.wait(timeout=interval)` so shutdown wakes the thread immediately instead of waiting up to 60s.
- ❌ **DO NOT** delete `'expired'` rows from `files` table. Keep them around for the audit trail; only `seen_nonces` actually shrinks.
- ❌ **DO NOT** physically delete ciphertext blobs from disk in this thread. Not in scope. (Future enhancement, not for M3 baseline.)
- ❌ **DO NOT** start the cleanup thread before `db_path` exists / schema is initialised. Order in `main.py`: init DB schema → start cleanup → `serve_forever`.

## References
- ARCHITECTURE.md §6 (concurrency model — cleanup thread, 60s interval, 5min retention)
- ARCHITECTURE.md §5 (`seen_nonces.seen_at` column)
- `zerotrust/server/replay.py` for `purge_old_nonces` API
