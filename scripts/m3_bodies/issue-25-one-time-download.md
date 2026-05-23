## Goal
**[BONUS]** A file is consumed exactly once: first `DOWNLOAD_RESPONSE` is served, but the row stays `'pending'` until the recipient's signed ACK arrives (#26). On ACK, the row flips to `'downloaded'` and any subsequent download attempt returns `ALREADY_DOWNLOADED`.

## Why this matters
Pairs with #26 to give the demo a "you only get it once" property. Without ACK, a transient network failure between server-send and client-decrypt would consume the only chance to retrieve the file. With ACK, the client confirms decrypt+verify success before the server burns the row.

## Dependencies
- **Blocked by:** #14 (`store.mark_status`), #17 (download handler), #19 (replay).
- **Pair:** #26 (the ACK side). The two issues land together or not at all.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | `_handle_download_request` no longer touches `status`. New `_handle_download_ack` does. |
| `zerotrust/tests/test_one_time_download.py` | **NEW** — first download succeeds, second pre-ACK still succeeds (network retry), post-ACK rejected. |

## State machine (FROZEN)
```
                        upload
                          ↓
                       'pending' ──────────── download served (no mark) ────┐
                          │                                                  │
                  expire  │  revoke                                          │
                          ↓                                                  ↓
                    'expired'                                       (waiting for ACK)
                                                                             │
                                                              valid ACK from recipient
                                                                             ↓
                                                                      'downloaded'
                                                                             │
                                                              another DOWNLOAD_REQUEST
                                                                             ↓
                                                                   ALREADY_DOWNLOADED
```

Note: `pending` is **both** "never delivered" and "delivered, awaiting ACK". The difference is observable only via the `acks` table.

## Implementation steps
1. `_handle_download_request`:
   - Run #16 chokepoint.
   - If `row["status"] != "pending"` → `ALREADY_DOWNLOADED` / `REVOKED` / `EXPIRED`.
   - Serve the package. **Do NOT** call `mark_status`.
2. `_handle_download_ack` (the new verb — #26 implements the wire side):
   - Replay check.
   - Verify ACK signature (sender_subject = session.peer_subject).
   - Insert into `acks` table (idempotent on file_id PK).
   - `store.mark_status(conn, file_id, "downloaded")`.
   - Reply `ACK_OK`.
3. Re-downloads BEFORE ACK arrives still work (legitimate network retry). Re-downloads AFTER ACK fail with `ALREADY_DOWNLOADED`.

## Acceptance criteria
- [ ] First `DOWNLOAD_REQUEST` succeeds; row still `'pending'`; `acks` table has no row.
- [ ] Second `DOWNLOAD_REQUEST` (before ACK) ALSO succeeds — covers network retry.
- [ ] Recipient sends `DOWNLOAD_ACK` → row flips to `'downloaded'`, `acks.file_id` populated.
- [ ] Third `DOWNLOAD_REQUEST` (after ACK) → `ALREADY_DOWNLOADED`.
- [ ] ACK without a previous successful download → server records it anyway (idempotent on `acks` PK; row state machine handles the rest).
- [ ] Replayed ACK envelope → `STALE`, row not double-marked.

## Required tests
- Happy one-time: download → ACK → second download rejected.
- Retry path: download → download (no ACK yet) → both succeed → ACK → third rejected.
- Forged ACK (signature from wrong key) → AUTH_FAILED, row stays pending.
- Replay ACK → STALE.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** mark `'downloaded'` inside the download handler. That breaks the retry-before-ACK property and reduces the bonus to "fire-and-forget" with no value over baseline.
- ❌ **DO NOT** trust `payload["sender"]` in the ACK. The signer is `session["peer_subject"]` (who must also be the row's `recipient_id`).
- ❌ **DO NOT** add a "force download even if downloaded" admin override. Not in scope, and any such bypass undermines the bonus.
- ❌ **DO NOT** physically delete the blob on ACK. Leave it on disk; the cleanup thread (#27) is the only thing that decides when bytes leave disk.

## References
- ARCHITECTURE.md §8 (bonus: one-time download, recipient ACK)
- ARCHITECTURE.md §5 (`acks` table — schema)
- ARCHITECTURE.md §11 (bonus features in scope)
