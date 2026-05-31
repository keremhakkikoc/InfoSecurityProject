## Goal
`python -m zerotrust.client.cli --user alice upload bob ./file.pdf [--expires-days 7]` reads the file from disk, encrypts it, wraps the key, signs the origin struct, builds an UPLOAD_REQUEST envelope, sends it, and prints the server's UPLOAD_ACK.

## Why this matters
This is the **demo-able** moment for M2: Alice physically uploads an encrypted file, server stores it, neither party ever leaks the plaintext.

## Dependencies
- **Blocked by:** #8 (session), #9 (CLI plumbing), #10 (file_crypto helper), #11a (key wrap), #11b (origin signature), #21 (need to fetch Bob's cert first).
- This is the **integration** issue — it consumes everything upstream.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/client/upload.py` | Replace stub with `upload_file(session, recipient_username, file_path, expiration_seconds)`. |
| `zerotrust/client/cli.py` | Wire the `upload` subcommand. |
| `zerotrust/tests/test_upload.py` | **NEW** — end-to-end upload against a real in-process server. |

## Function signature
```python
def upload_file(
    session: dict,                # from perform_client_handshake
    recipient_username: str,
    file_path: str,
    expiration_seconds: int = 7 * 86400,
) -> dict:
    """Return the server's UPLOAD_ACK payload on success. Raises on failure."""
```

## Implementation steps
1. `recipient_cert = fetch_peer_cert(session, recipient_username)` (uses GET_PUBKEY — #21).
2. Verify recipient_cert against the CA trust anchor + subject == recipient_username. If invalid, abort.
3. Read `file_path` from disk. (For M2, keep the whole file in memory — chunking is out of scope.)
4. Generate `file_id = str(uuid.uuid4())`.
5. `nonce, ciphertext, aes_key = encrypt_file_blob(plaintext, file_id, sender=alice, recipient=bob)` (#10).
6. `wrapped_key = wrap_aes_key_for(recipient_cert, aes_key)` (#11a).
7. Compute `ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()` and same for `wrapped_key`.
8. `timestamp = int(time.time())`, `expiration = timestamp + expiration_seconds`.
9. `signature = sign_origin_struct(alice_priv, alice_password, sender=..., recipient=..., file_id=..., ciphertext_sha256=..., wrapped_key_sha256=..., timestamp=..., expiration=...)` (#11b).
10. Build UPLOAD_REQUEST envelope with base64-encoded binary fields:
    ```json
    {
      "file_id": "...",
      "recipient": "bob",
      "ciphertext": "<base64>",
      "nonce": "<base64>",
      "wrapped_key": "<base64>",
      "signature": "<base64>",
      "timestamp": ...,
      "expiration": ...
    }
    ```
11. (Once the post-handshake encrypted-channel work lands) encrypt the envelope with `c2s_key` before send. **For M2, sending plaintext envelope is acceptable** — the ciphertext is already protected by AES-GCM; the channel encryption is defence-in-depth.
12. `send_message(sock, envelope)`, await `UPLOAD_ACK`.
13. Print `Uploaded file_id=<uuid> to bob; expires=<unix>`. Return the ACK payload.

## Acceptance criteria
- [ ] `make ca-init && make ca-issue USER=alice && make ca-issue USER=bob` followed by `python -m zerotrust.server.main` then `python -m zerotrust.client.cli --user alice upload bob ./test.txt` returns ACK and the server writes a `*.bin` file.
- [ ] Server's stored file is binary garbage (proves ciphertext) — `file server/storage/files/<id>.bin` says "data".
- [ ] If Bob does not have a cert in the public key directory → `NOT_FOUND` error, no file written.
- [ ] If `file_path` doesn't exist → exits 1 with `FILE_NOT_FOUND` (don't hit the network).
- [ ] Tampering with any envelope field server-side is caught by #13 (covered there).

## Required tests
- End-to-end upload in a single process with two threads (server + client).
- Recipient's cert missing → error path.
- File too big (just over `MAX_MESSAGE_BYTES`) → clean refusal.

## Pitfalls
- Do NOT include the `aes_key` anywhere in the envelope — that defeats the whole zero-trust premise. Only `wrapped_key` goes on the wire.
- Do NOT compute the sha256 of the **plaintext** — it leaks information about file content to the server. Hash only the ciphertext and wrapped key.
- Base64 encode every binary field in JSON.
- Keep the file-read in `with open(...) as f: f.read()` style so the file handle closes even on errors.

## References
- ARCHITECTURE.md §8 (file lifecycle — upload)
- ARCHITECTURE.md §7.3 (UPLOAD_REQUEST / UPLOAD_ACK)
- ARCHITECTURE.md §7.6 (origin signature struct)
