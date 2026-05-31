## Goal
**[BONUS]** After `verify_and_decrypt_download` succeeds locally, the recipient signs `{file_id, "received", timestamp}` (canonical JSON) and sends `DOWNLOAD_ACK`. The server verifies the signature with the recipient's cert and stores it in the `acks` table. Paired with #25 to give one-time-download semantics.

## Why this matters
Without an ACK, the server can't tell "decrypt+verify failed for Bob" from "Bob just got it cleanly". The signed ACK is the trust handshake on the way back — non-repudiation that Bob really did receive the file intact.

## Dependencies
- **Blocked by:** #18 (recipient verify+decrypt), #19 (replay enforcement).
- **Pair:** #25 (which flips the row state on ACK).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/client/download.py` | After `verify_and_decrypt_download` returns plaintext, send a signed `DOWNLOAD_ACK`. |
| `zerotrust/server/handler.py` | New `_handle_download_ack` dispatch (the wire side; #25 owns the state machine effect). |
| `zerotrust/server/store.py` | Add `insert_ack(conn, file_id, ack_signature, ack_timestamp)` if not already present. Schema in ARCHITECTURE.md §5 has the `acks` table. |
| `zerotrust/tests/test_download_ack.py` | **NEW** — happy, forged ACK rejected, replay rejected, ACK without prior download tolerated. |

## DOWNLOAD_ACK payload (signed by recipient)
```python
{
    "file_id":   str,
    "status":    "received",
    "timestamp": int,
    "signature": "<base64>",   # RSA-PSS over canonical_json of the above 3 fields
}
```

## Implementation steps (recipient)
1. `verify_and_decrypt_download` returns plaintext. **Only now** build the ACK.
2. `canonical = canonical_json({"file_id": file_id, "status": "received", "timestamp": now})`
3. `signature = rsa_sign(my_priv, my_password, canonical)`
4. `send_message(sock, make_envelope("DOWNLOAD_ACK", {...}))`
5. Receive `ACK_OK` (or `STALE` on replay). Either way, write the plaintext to disk.

## Implementation steps (server)
1. Replay check.
2. `row = store.get_file(conn, file_id)`. None → `NOT_FOUND` (silently — we still recorded the ACK attempt in logs).
3. `session["peer_subject"] == row["recipient_id"]` — only the addressed recipient can ACK.
4. Recompute canonical → `rsa_verify(session_peer_pubkey_pem, canonical, signature)`. Fail → `AUTH_FAILED`.
5. `store.insert_ack(conn, file_id, signature, timestamp)`. PK on `file_id` → idempotent.
6. Trigger #25's state-machine effect (`store.mark_status(conn, file_id, "downloaded")`).
7. Reply `ACK_OK`.

## Acceptance criteria
- [ ] Happy: Bob downloads → decrypts → ACKs → row in `acks` table with valid signature.
- [ ] Forged ACK (signature from wrong key, but session is Bob's) → AUTH_FAILED. No `acks` row inserted.
- [ ] ACK signed by Carol for a Bob-recipient row → NOT_AUTHORIZED.
- [ ] Replayed ACK → STALE. Existing `acks` row unchanged.
- [ ] Recipient runs decrypt → ACK → decrypt+ACK again later: ACK is idempotent (PK conflict caught), status stays `'downloaded'`.

## Required tests
- Happy ACK + DB row inserted + status flipped.
- Forged ACK (sign with key_A, present cert with pubkey_B) — server's RSA verify catches it.
- Wrong-recipient ACK (Carol tries to ACK Alice→Bob row).
- Replay ACK envelope.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** ACK BEFORE decryption succeeds. The whole non-repudiation property is "I, recipient, vouch I got it intact" — ACKing before verify defeats it.
- ❌ **DO NOT** sign a non-canonical string. Use `canonical_json({...})` so server and client agree byte-for-byte. Roll-your-own format = signature mismatch.
- ❌ **DO NOT** trust `payload["sender"]` field in the ACK if you add one (don't add one). Source of truth is `session["peer_subject"]`.
- ❌ **DO NOT** suppress `CryptoError` from the verify path and ACK anyway. If verify fails, no ACK should go out at all.
- ❌ **DO NOT** store the raw signature in logs. `fingerprint(signature)` is fine.

## References
- ARCHITECTURE.md §5 (`acks` table schema)
- ARCHITECTURE.md §8 (bonus: signed ACK)
