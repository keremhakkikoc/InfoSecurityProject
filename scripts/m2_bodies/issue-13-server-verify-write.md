## Goal
On UPLOAD_REQUEST, server (a) verifies sender cert against CA, (b) verifies sender's session PoP, (c) verifies origin signature, (d) checks freshness, (e) writes ciphertext to disk + inserts metadata row, (f) returns UPLOAD_ACK.

## Why this matters
This is the **gate** between "anyone can post bytes" and "only authenticated, verified senders can store on this server." Every single check has a reason; skipping one creates a real attack.

## Dependencies
- **Pairs with:** #11b (you call its `verify_origin_struct`).
- **Blocked by:** #8 (session must exist), #14 (need DB for the metadata row to land), #6 (cert verify).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | Add `_handle_upload_request(conn, session, payload)`. |
| `zerotrust/server/main.py` | Dispatch UPLOAD_REQUEST → `_handle_upload_request`. |
| `zerotrust/tests/test_server_upload.py` | **NEW** — at least 6 cases (one happy, five failure modes). |

## Verification order (FAIL CLOSED at every step)
```python
def _handle_upload_request(conn, session, payload):
    # 1. Replay protection (cheap, do first to avoid DoS via expensive checks).
    nonce = base64.b64decode(envelope["nonce"])
    if not check_and_record(thread_conn, nonce, envelope["timestamp"]):
        return _error(conn, "STALE")  # or "REPLAY" — same generic to client

    # 2. Sender PoP: did this session prove ownership of the cert it presented?
    #    Already done at handshake time; session["peer_subject"] is trusted.
    sender_subject = session["peer_subject"]

    # 3. Decode payload fields. Base64 -> bytes for ciphertext/nonce/wrapped/sig.
    # ... decode ...

    # 4. Recompute ciphertext_sha256 and wrapped_key_sha256 from the actual bytes.
    #    Compare to the values declared in payload — must match or origin signature
    #    won't recompute. (Belt-and-braces: detects tampering even before sig check.)

    # 5. verify_origin_struct(session["peer_cert"], signature, ...all fields...)
    if not verify_origin_struct(session["peer_cert"], signature, ...):
        log.warning("origin verify failed for %s", sender_subject)
        return _error(conn, "AUTH_FAILED")

    # 6. Sanity-check recipient exists in pubkey directory (#21).
    if not _recipient_exists(payload["recipient"]):
        return _error(conn, "NOT_FOUND")

    # 7. Write ciphertext to disk atomically.
    blob_path = f"server/storage/files/{file_id}.bin"
    tmp = blob_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(ciphertext)
    os.rename(tmp, blob_path)

    # 8. Insert metadata row (#14).
    store.insert_file(thread_conn, {...})

    # 9. UPLOAD_ACK with file_id + expiration.
    send_message(conn, make_envelope("UPLOAD_ACK", {"file_id": ..., "expiration": ...}))
    log.info("upload accepted file=%s sender=%s recipient=%s",
             file_id, sender_subject, payload["recipient"])
```

## Acceptance criteria
- [ ] Happy path: client's upload succeeds, file is on disk, row in DB, ACK received.
- [ ] Tampered ciphertext (intercepted in flight) → AUTH_FAILED, no disk write, no row, no leak of the actual reason to client.
- [ ] Forged signature (different signer) → AUTH_FAILED.
- [ ] Stale timestamp (50s old) → STALE, no write.
- [ ] Replayed nonce (same upload twice) → REPLAY on the second one.
- [ ] Unknown recipient → NOT_FOUND.
- [ ] Atomic disk write: kill the server mid-write → no half-files in `files/`.

## Required tests
- All 6 acceptance bullets, each its own test function.

## Pitfalls
- Do NOT trust `payload["sender"]` over `session["peer_subject"]` — the latter is what your handshake proved. If they differ, REJECT immediately (impersonation attempt).
- Do NOT write the ciphertext directly to its final path — write to `*.tmp` then `os.rename`. Otherwise a crash mid-write leaves corrupt rows.
- Do NOT log the wrapped_key, ciphertext, or signature bytes — only their sha256 prefixes if at all. AI.md §3.
- The server doesn't (and can't) verify the AES key or plaintext — its job is **only** to verify the signature over the canonical struct.

## References
- ARCHITECTURE.md §7.6 (origin signature — what to verify)
- ARCHITECTURE.md §7.8 (replay protection)
- ARCHITECTURE.md §7.9 (error codes — generic only)
- ARCHITECTURE.md §8 (file lifecycle)
- AI.md §3, §4 (logging, generic errors)
