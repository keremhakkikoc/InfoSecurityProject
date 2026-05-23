## Goal
**[BONUS]** Sender can recall a still-pending upload before the recipient downloads it. New `REVOKE_REQUEST` message: server verifies the requester owns the file, sets `status='revoked'`, subsequent download attempts get `REVOKED`.

## Why this matters
Real "drop" UX. Alice uploaded the wrong file → she can pull it back as long as Bob hasn't downloaded yet. The bonus point comes from the assignment PDF.

## Dependencies
- **Blocked by:** #14 (`store.mark_status`), #16 (authorisation chokepoint), #19 (replay protection).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | New dispatch case `_handle_revoke_request`. |
| `zerotrust/client/cli.py` | New subcommand: `revoke <file_id>`. |
| `zerotrust/client/revoke.py` (or extend `upload.py`) | Helper `revoke_file(session, file_id)` that builds + sends signed REVOKE_REQUEST. |
| `zerotrust/tests/test_revocation.py` | **NEW** — happy, not-owner rejected, already-downloaded rejected, double-revoke idempotent. |

## REVOKE_REQUEST payload (signed by sender)
```python
{
    "file_id":   str,
    "timestamp": int,
    "signature": "<base64>",   # RSA-PSS over canonical struct (below)
}
```
Canonical struct (signed):
```python
{"action": "revoke", "file_id": ..., "sender": ..., "timestamp": ...}
```

## Implementation steps (server)
1. Replay check (envelope nonce) — same pattern as upload.
2. Look up the file row: `row = store.get_file(conn, payload["file_id"])`. None → `NOT_FOUND`.
3. **Ownership:** `row["sender_id"] == session["peer_subject"]`. Otherwise `NOT_AUTHORIZED`.
4. **Signature:** recompute the canonical revoke struct (`canonical_json`), `rsa_verify` with the session's peer pubkey. Fail → `AUTH_FAILED`.
5. **State machine:** only `pending` rows can be revoked. `downloaded` → `ALREADY_DOWNLOADED`. `expired` / `revoked` → `EXPIRED` / `REVOKED` (idempotent — re-revoking is a no-op success).
6. `store.mark_status(conn, file_id, "revoked")`.
7. Reply `REVOKE_ACK {file_id, status}`.

## Acceptance criteria
- [ ] Alice revokes her own pending upload → row status flips to `'revoked'`.
- [ ] Bob tries to download afterwards → `REVOKED` error, no blob bytes shipped.
- [ ] Mallory tries to revoke Alice's file → `NOT_AUTHORIZED`. Row unchanged.
- [ ] Alice tries to revoke after Bob downloaded → `ALREADY_DOWNLOADED`. Row stays `'downloaded'`.
- [ ] Alice revokes the same file twice → second call returns success (idempotent), no log noise.
- [ ] Revoke without a valid signature → `AUTH_FAILED`.

## Required tests
- Happy revoke.
- Non-owner revoke attempt.
- Revoke after download (or one-time bonus mark).
- Forged signature (sign with a different key, present Alice's cert) → AUTH_FAILED.
- Replay revoke envelope → STALE.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** allow revoke based on `payload["sender"]`. Use `session["peer_subject"]` and re-verify against the row's `sender_id`.
- ❌ **DO NOT** physically delete the ciphertext blob from disk on revoke. Just flip the status. Deletion is the cleanup thread's job (#27, optional). Disk-touching in a request handler creates atomicity bugs.
- ❌ **DO NOT** skip the signature verification because "we already authenticated the session". The handshake proved who's connected; the per-request signature proves the request itself wasn't forged inside an authenticated session by a buggy client.
- ❌ **DO NOT** sign a non-canonical string. Use `canonical_json({...})` byte-for-byte on both sides.
- ❌ **DO NOT** roll your own SQL update — use `store.mark_status(conn, file_id, "revoked")`. It already validates the status value.

## References
- ARCHITECTURE.md §8 (file lifecycle — revocation)
- ARCHITECTURE.md §11 (bonus features in scope)
