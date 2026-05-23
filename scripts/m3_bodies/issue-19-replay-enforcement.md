## Goal
Wire `zerotrust.server.replay.check_and_record` into **every** state-changing request handler (UPLOAD_REQUEST, DOWNLOAD_REQUEST, REVOKE_REQUEST, DOWNLOAD_ACK). Reject `STALE` (timestamp drift > 30s) and `REPLAY` (nonce already seen in the last 5 minutes) deterministically.

## Why this matters
An attacker who captures a legitimate request on the wire and re-sends it must not be able to trigger the side effect a second time. Especially: a captured DOWNLOAD_REQUEST replayed two days later would otherwise re-deliver the file even after Bob already got it.

## Dependencies
- **Blocked by:** `replay.check_and_record` (M1).
- **Pairs with:** #27 (cleanup thread that purges `seen_nonces` older than 5 minutes).
- **Used by:** every state-changing handler.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | First check in every `_handle_*` is `if not replay.check_and_record(...): return STALE/REPLAY`. Already present in `_handle_upload_request` from #13 — extend to download, revoke, ack. |
| `zerotrust/tests/test_replay_enforcement.py` | **NEW** — end-to-end replay attack against each verb. |

## Window & retention (FROZEN by ARCHITECTURE.md §7.8)
- Accept `abs(now - msg.timestamp) <= 30` seconds.
- Reject nonce if already in `seen_nonces` (last 5 minutes).
- Single failure case → `STALE` to the wire (we conflate `STALE` and `REPLAY` to avoid leaking which one tripped).

## Implementation steps
1. For each state-changing handler, before any expensive work:
   ```python
   try:
       nonce = base64.b64decode(envelope["nonce"], validate=True)
   except Exception:
       _send_error(sock, "MALFORMED"); return
   if not replay.check_and_record(thread_conn, nonce, envelope["timestamp"]):
       _send_error(sock, "STALE"); return
   ```
2. Reads (`GET_PUBKEY`, `LIST_PENDING`) are idempotent and DO NOT require replay protection at the application level. Skipping is intentional — adds no security and would create user-visible "intermittent STALE" bugs when nonces collide harmlessly.

## Acceptance criteria
- [ ] Captured `UPLOAD_REQUEST` replayed → server rejects, no second blob on disk.
- [ ] Captured `DOWNLOAD_REQUEST` replayed → server rejects.
- [ ] Captured `REVOKE_REQUEST` (#24) replayed → server rejects.
- [ ] Captured `DOWNLOAD_ACK` (#26) replayed → server rejects, doesn't double-mark.
- [ ] Stale timestamp (50s old) → reject.
- [ ] Future timestamp (clock skew >30s ahead) → reject.
- [ ] Reads (`LIST_PENDING`, `GET_PUBKEY`) replayed → NOT rejected (they're idempotent).
- [ ] All rejection paths log full reason server-side; client only sees `STALE`.

## Required tests
- Replay upload: send identical envelope twice on same socket → first ACK, second STALE.
- Replay across connections: capture envelope bytes, open fresh socket + handshake, replay → STALE.
- Stale timestamp: hand-craft envelope with `timestamp = now() - 60` → STALE.
- Future timestamp: `timestamp = now() + 60` → STALE.
- Cleanup interaction: insert a nonce → fast-forward `time.time` by 6 minutes → cleanup deletes it → same nonce now accepted (proves cleanup window works).

## Pitfalls — DO NOT do these
- ❌ **DO NOT** use a module-level `SEEN_NONCES = set()`. That's not thread-safe AND doesn't persist across server restarts. **Past mistake (#13):** Kerem wrote exactly this — `SEEN_NONCES = set()` with a `check_and_record_nonce` stub. Use `zerotrust.server.replay.check_and_record(conn, nonce, ts)` which uses the SQLite `seen_nonces` table.
- ❌ **DO NOT** compare nonces with `==`. The replay table uses SQLite `PRIMARY KEY` constraint which gives constant-time set membership at the storage layer; you do not need (and shouldn't add) a Python-level check.
- ❌ **DO NOT** widen the 30s window to "be lenient about clock skew". The window is part of the spec; widening it widens the replay surface linearly with whatever you choose.
- ❌ **DO NOT** return distinct error codes for STALE vs REPLAY. An attacker learning which one tripped knows whether their nonce collided (replay) or just timed out (stale). Conflate to `STALE`.
- ❌ **DO NOT** skip the replay check on the grounds that the upload signature already binds a nonce. The signature stops forged uploads; the replay table stops legitimate-signed-but-replayed uploads.

## References
- ARCHITECTURE.md §7.8 (replay protection — window, retention, table schema)
- ARCHITECTURE.md §5 (`seen_nonces` table)
- M1 `zerotrust/server/replay.py` for the helper API
