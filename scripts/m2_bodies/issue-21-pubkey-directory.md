## Goal
Implement the public key directory: server stores each registered user's CA-signed cert under `server/storage/pubkeys/<username>.json`. Clients fetch via `GET_PUBKEY`, server replies with `PUBKEY_RESPONSE` carrying the cert.

## Why this matters
Alice needs Bob's pubkey to wrap the per-file AES key (#11a). Asking the server for it is the natural place — the server already has every user's cert from the CA. Because the cert is CA-signed, Alice can trust it without trusting the server (zero-trust property preserved).

## Dependencies
- **Used by:** #12 (upload — fetches recipient's cert first).
- **Blocked by:** none.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | Add `_handle_get_pubkey(conn, payload)`. |
| `zerotrust/server/storage_layout.py` | **NEW** (or in `handler.py`) — `pubkey_path_for(username)` helper. |
| `zerotrust/client/peer.py` | **NEW** — `fetch_peer_cert(session, username) -> dict`. |
| `zerotrust/tests/test_pubkey_directory.py` | **NEW** — happy + unknown user + path traversal attempt. |

## Cert distribution to the server
The CA writes `users/<name>/cert.json`. For M2, **the team manually copies** each issued cert into `server/storage/pubkeys/<name>.json` after running `make ca-issue`. Document this in the README under "demo setup". Automating this is M3 polish.

## Message shapes
**GET_PUBKEY** payload:
```json
{"username": "bob"}
```
**PUBKEY_RESPONSE** payload (success):
```json
{"cert": {<the full cert JSON>}}
```
**ERROR** (unknown user):
```json
{"code": "NOT_FOUND"}
```

## Implementation steps (server)
1. Sanitise `username`: must match `^[a-zA-Z0-9_-]{1,32}$`. Anything else → NOT_FOUND. **This blocks `../` traversal.**
2. Read `server/storage/pubkeys/<username>.json` if it exists.
3. Parse it; verify it against the server's CA trust anchor before returning (defence in depth — catches a malicious filesystem state).
4. Send PUBKEY_RESPONSE.

## Implementation steps (client)
1. `send_message(sock, make_envelope("GET_PUBKEY", {"username": username}))`.
2. `recv_message(sock)` — must be PUBKEY_RESPONSE.
3. Verify the returned cert against the local CA trust anchor + subject == username.
4. Return the cert dict.

## Acceptance criteria
- [ ] Alice can fetch Bob's cert and verify it against her local CA.
- [ ] Asking for a non-existent user → NOT_FOUND, no filesystem error to client.
- [ ] Path traversal attempt (`username="../../etc/passwd"`) → NOT_FOUND, refused at regex.
- [ ] If the file on disk is corrupted (bad JSON or bad signature), server returns NOT_FOUND (don't expose internal error).

## Required tests
- Happy fetch.
- Unknown user.
- Path traversal: `"../"`, `".."`, `"/etc/passwd"`, `"a/b"` — all rejected.
- Corrupted pubkey file on server → NOT_FOUND.

## Pitfalls
- The regex IS the security boundary. Anchor it (`^...$`). Don't accept dots, slashes, or null bytes.
- Server verifying its own pubkey files against the CA trust anchor before returning means an attacker who plants a fake `bob.json` on the filesystem still can't impersonate Bob — the cert won't verify.
- Client MUST verify the returned cert against the **local** CA trust anchor, not just trust the server's word. This is what makes the channel zero-trust.

## References
- ARCHITECTURE.md §7.3 (message types)
- ARCHITECTURE.md §4.1 (server storage layout — pubkeys/)
