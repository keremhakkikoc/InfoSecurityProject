## Goal
Implement the `DOWNLOAD_REQUEST` / `DOWNLOAD_RESPONSE` round trip. Recipient asks by `file_id`; server (after the #16 authorisation chokepoint) ships the full encrypted package — ciphertext bytes, AES nonce, AAD, RSA-OAEP-wrapped key, sender signature, sender cert.

## Why this matters
This is the byte-pump for the demo: Bob runs `download <file_id>` and a real encrypted file lands in `client_bob/downloads/`. Everything before this is metadata plumbing; this is where the deliverable actually flows.

## Dependencies
- **Blocked by:** #14 (`store.get_file`), #16 (authorisation chokepoint).
- **Used by:** #18 (recipient-side decrypt + verify), #23 (integration test).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | New dispatch case `_handle_download_request`. Calls #16 chokepoint → reads blob from `file_blob_path_for(...)` → builds response envelope. |
| `zerotrust/client/download.py` | `download_file(session, file_id, output_dir) -> str`. Returns absolute path of decrypted file on disk. |
| `zerotrust/client/cli.py` | New subcommand: `download <file_id>`. |
| `zerotrust/tests/test_download.py` | **NEW** — happy roundtrip, NOT_AUTHORIZED, EXPIRED, NOT_FOUND. |

## Frozen helpers you MUST use
```python
from zerotrust.common.protocol import make_envelope, send_message, recv_message, validate_envelope
from zerotrust.server.store import get_file
from zerotrust.server.storage_layout import file_blob_path_for
```

## DOWNLOAD_RESPONSE payload shape (FROZEN)
```python
{
    "file_id":            str,         # echo of the request
    "sender_id":          str,
    "ciphertext":         "<base64>",   # AES-GCM ciphertext + tag
    "nonce":              "<base64>",   # 12 bytes
    "aad":                "<base64>",   # the f"{file_id}|{sender}|{recipient}" bytes
    "wrapped_key":        "<base64>",   # RSA-OAEP under recipient's pubkey
    "sender_signature":   "<base64>",   # RSA-PSS over canonical origin struct
    "sender_cert":        {...},        # full JSON cert dict, CA-verified at upload time
    "timestamp":          int,
    "expiration":         int,
}
```

Issue #18 is the corresponding verifier; field names MUST match.

## Implementation steps (server)
1. `validate_envelope` the incoming `DOWNLOAD_REQUEST`, extract `file_id`.
2. Run #16's authorisation chokepoint. On any non-OK, `_send_error(sock, code)` and return.
3. Read the ciphertext blob from disk: `blob = file_blob_path_for(server_state, file_id).read_bytes()`.
4. Recompute `sha256(blob)` and compare to `row["ciphertext_sha256"]`. If mismatch, the disk has been tampered with → `INTERNAL_ERROR` + log loud.
5. Assemble the response envelope (shape above). Base64-encode every binary field.
6. `send_message(sock, make_envelope("DOWNLOAD_RESPONSE", payload))`.

## Implementation steps (client)
Verification + decrypt lives in #18. **This** issue just provides the network round trip + writes the decrypted output. Concretely:
1. After handshake, send `DOWNLOAD_REQUEST {"file_id": file_id}`.
2. Receive envelope; if `type == "ERROR"`, raise `AuthError(payload["code"])`.
3. Pass response payload through `verify_and_decrypt_download(...)` (#18).
4. Write plaintext to `client_<user>/downloads/<original_filename or file_id>`.
5. Return that path.

## Acceptance criteria
- [ ] Demo flow works: Alice uploads file `report.pdf` → Bob runs `download <file_id>` → bit-identical file appears in `client_bob/downloads/`.
- [ ] Carol's download request for Alice→Bob's file → server returns `NOT_AUTHORIZED` envelope; NO bytes of ciphertext go on the wire.
- [ ] Expired file → `EXPIRED`. Client surfaces this as a clean error, exits non-zero.
- [ ] Unknown `file_id` → `NOT_FOUND`.
- [ ] If the on-disk blob was tampered after upload (someone with shell access modifies `*.bin`), server's sha256 re-check catches it → no corrupted file leaks to client.

## Required tests
- End-to-end roundtrip with two in-process threads (server + client). Plaintext recovered must equal plaintext sent.
- `NOT_AUTHORIZED`: alice's session asks for a row recipient=bob → error, no blob written.
- `EXPIRED`: monkeypatch clock past `expiration`.
- Tampered blob: after upload, modify one byte of `*.bin` on disk → download returns `INTERNAL_ERROR`, client surfaces error, no decrypted file written.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** check authorisation inside the download handler ad-hoc. Call #16's `_authorise_download` chokepoint. Duplicating the check splits the source of truth.
- ❌ **DO NOT** trust `payload["recipient"]` in `DOWNLOAD_REQUEST`. The only field that should come from the requester is `file_id`. Everything else comes from the stored row + session.
- ❌ **DO NOT** mark the row `'downloaded'` here. The bonus one-time semantics (#25) move that to AFTER the recipient ACK (#26). For M3 baseline, status stays `'pending'`.
- ❌ **DO NOT** stream the blob byte-by-byte with raw `sock.send` — use `protocol.send_message`. Length-prefixed JSON envelope is mandatory.
- ❌ **DO NOT** decrypt server-side, ever. The server never touches the AES key; it cannot, because the wrapped key is OAEP'd under the recipient's pubkey.
- ❌ **DO NOT** import `cryptography.x509`. We use **custom JSON certs** (ARCHITECTURE.md §3.2). The `sender_cert` field is a dict, not a PEM you need to parse.

## References
- ARCHITECTURE.md §7.3 (DOWNLOAD_REQUEST / DOWNLOAD_RESPONSE)
- ARCHITECTURE.md §8 (file lifecycle — download)
- ARCHITECTURE.md §7.7 (AAD format — must be regenerated by recipient bit-for-bit)
