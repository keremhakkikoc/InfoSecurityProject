## Goal
On every download attempt, the server enforces **three** checks before serving any byte:
1. The asking session's `peer_subject` matches the row's `recipient_id` (authorisation).
2. The row's `status` is `'pending'` (not `downloaded` / `expired` / `revoked`).
3. `expiration > int(time.time())` (still in date).

Each failure surfaces a single opaque error code; no internal reason leaks.

## Why this matters
The whole zero-trust property is undone if Carol can download Alice→Bob's file. Expiration is the user-facing "drop window" — past it, the file is treated as if it never existed. These checks live in **one** chokepoint (the download handler) so all paths converge to the same enforcement.

## Dependencies
- **Blocked by:** #14 (`store.get_file`), #8 (handshake gives `peer_subject`).
- **Used by:** #17 (download request), #24 (revocation reuses the chokepoint).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | Add `_authorise_download(session, row) -> tuple[bool, str]` chokepoint. Returns `(True, "")` or `(False, "NOT_AUTHORIZED" / "EXPIRED" / "NOT_FOUND")`. |
| `zerotrust/tests/test_download_access.py` | **NEW** — 3 rejection paths + 1 happy. |

## Error code mapping (ARCHITECTURE.md §7.9)
| Internal reason | Wire code |
|---|---|
| `recipient_id != peer_subject` | `NOT_AUTHORIZED` |
| `status == 'expired'` or `expiration <= now()` | `EXPIRED` |
| `status == 'revoked'` | `REVOKED` |
| `status == 'downloaded'` (bonus one-time) | `ALREADY_DOWNLOADED` |
| Row doesn't exist | `NOT_FOUND` |

Each is logged with full detail server-side, but the **client receives only the code**.

## Implementation steps
1. Look up the row: `row = store.get_file(conn, file_id)`. If `None` → `NOT_FOUND`.
2. Check authorisation: `row["recipient_id"] == session["peer_subject"]`. Otherwise `NOT_AUTHORIZED`. Use plain `==` (subject is public, no timing side-channel).
3. Check expiration: `row["expiration"] > int(time.time())`. Otherwise `EXPIRED` AND opportunistically `store.mark_status(conn, file_id, "expired")` to keep the DB tidy.
4. Check status: `row["status"] == "pending"` → proceed. Anything else maps via the table above.
5. On success, **caller** is responsible for the download response itself (issue #17). This handler only authorises.

## Acceptance criteria
- [ ] Carol asking for Alice→Bob's file → `NOT_AUTHORIZED`. NO blob bytes sent.
- [ ] Bob asking after expiration → `EXPIRED`. Row's status updated to `'expired'`.
- [ ] Bob asking for a `file_id` that doesn't exist → `NOT_FOUND`.
- [ ] Bob asking for a revoked file → `REVOKED` (bonus interaction, #24).
- [ ] Audit log records all four rejection types with `file_id`, `requester=peer_subject`, real reason.

## Required tests
- Happy: row exists, recipient matches, in-date, pending → returns `(True, "")`.
- Wrong recipient: build a row with `recipient_id="bob"`, ask with `peer_subject="carol"` → `NOT_AUTHORIZED`.
- Expired: monkeypatch `time.time` to row's `expiration + 1` → `EXPIRED` + status updated to `'expired'`.
- Not found: ask with a fresh UUID → `NOT_FOUND`.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** trust `payload["recipient"]` for the authorisation check. Source of truth is `session["peer_subject"]`. Past mistake: `sender = payload.get("sender")` in #13 — same anti-pattern, don't repeat.
- ❌ **DO NOT** return different error messages for "not yours" vs "doesn't exist". Both should be `NOT_FOUND`-or-`NOT_AUTHORIZED`-style opaque codes; never "file exists but not yours" (that leaks existence info).
- ❌ **DO NOT** use `hmac.compare_digest` for subject equality. AI.md §1.13 mandates it for **secrets**; subjects are public identifiers.
- ❌ **DO NOT** roll your own clock — use `int(time.time())`. Mockability comes from `monkeypatch.setattr("time.time", ...)`.
- ❌ **DO NOT** silently downgrade a `REVOKED` to `EXPIRED` or `NOT_FOUND` — the exact reason matters for the audit log even if it's hidden from the client.

## References
- ARCHITECTURE.md §8 (file lifecycle — expiration, revocation)
- ARCHITECTURE.md §7.9 (error codes — generic to client, detailed in logs)
- AI.md §4 (generic responses to clients)
