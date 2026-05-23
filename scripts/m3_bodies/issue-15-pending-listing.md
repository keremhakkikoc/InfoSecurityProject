## Goal
Recipient can ask the server "which files are waiting for me?" and get back a list of metadata rows for **pending, non-expired** files addressed to them.

## Why this matters
Without this, Bob has no way to discover that Alice uploaded a file. Recipient pull (rather than server push) is also a privacy property: the server never has to enumerate any user's inbox to anyone but that user.

## Dependencies
- **Blocked by:** #14 (`store.list_pending_for`), #8 (handshake to know who's asking).
- **Used by:** #17 (download — UI typically lists pending then downloads one).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | New dispatch case for `LIST_PENDING`. Calls `store.list_pending_for(conn, session["peer_subject"])`. |
| `zerotrust/client/download.py` | New helper `list_pending(session) -> list[dict]`. |
| `zerotrust/client/cli.py` | New subcommand: `python -m zerotrust.client.cli --user bob list`. |
| `zerotrust/tests/test_pending_list.py` | **NEW** — happy + recipient isolation + expired filter + empty list. |

## Frozen helpers you MUST use
```python
from zerotrust.common.protocol import make_envelope, send_message, recv_message, validate_envelope
from zerotrust.server.store import list_pending_for
```

## Implementation steps (server)
1. Receive `LIST_PENDING` envelope inside the post-handshake loop.
2. `recipient = session["peer_subject"]` — NEVER from payload (would let any user list any inbox).
3. `rows = list_pending_for(thread_conn, recipient)` — already filters `status='pending' AND expiration > now()`.
4. Strip sensitive blob fields before returning (we don't need to send `ciphertext_path` or the cert blob in a listing — just `file_id`, `sender_id`, `upload_timestamp`, `expiration`, byte sizes).
5. Reply with `make_envelope("PENDING_LIST", {"files": [...]})`.

## Implementation steps (client)
1. After handshake, `send_message(sock, make_envelope("LIST_PENDING", {}))`.
2. `reply = validate_envelope(recv_message(sock))`; assert `reply["type"] == "PENDING_LIST"`.
3. Pretty-print: `file_id  sender  size  expires-in`.

## Acceptance criteria
- [ ] Alice uploads → Bob's `list` shows exactly one row with the right `file_id`.
- [ ] Alice uploads to Bob → **Carol's** `list` is empty (recipient isolation).
- [ ] Expired files do NOT appear (covered by `store.list_pending_for` query).
- [ ] Empty inbox returns `PENDING_LIST` with `files=[]`, not an error.

## Required tests
- Happy: one upload → listed once.
- Isolation: Alice uploads to Bob → Carol's `LIST_PENDING` returns `[]`.
- Expired filter: force-expire a row by setting `expiration` in the past → omitted from listing.
- Replay (cheap): two listings in a row both succeed (LIST_PENDING is idempotent, no envelope nonce reuse).

## Pitfalls — DO NOT do these
- ❌ **DO NOT** read `recipient` from the request payload. Always trust `session["peer_subject"]` (set by `perform_server_handshake` from the verified peer cert).
- ❌ **DO NOT** include `wrapped_key`, `sender_signature`, or other large blobs in the listing — that's the job of `DOWNLOAD_RESPONSE` (#17). Listing is metadata-only.
- ❌ **DO NOT** import `cryptography.x509` — we use **custom JSON certs**. The cert dict comes from `store.get_file()` and was already verified at upload time.
- ❌ **DO NOT** write your own SQL query that joins / filters — use `store.list_pending_for` (issue #14). If you need a new query, add it to `store.py` with a new function, not inline.
- ❌ **DO NOT** dispatch on a raw `sock.recv(4096)` — use `recv_message(sock)` + `validate_envelope`. Anything else breaks framing.

## References
- ARCHITECTURE.md §7.3 (message types: LIST_PENDING / PENDING_LIST)
- ARCHITECTURE.md §8 (file lifecycle — list)
- AI.md §4 (generic errors only — if `peer_subject` is somehow None, return NOT_FOUND, not detail)
