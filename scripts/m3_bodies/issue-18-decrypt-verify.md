## Goal
Implement `verify_and_decrypt_download(payload, my_priv_pem, my_password, ca_pubkey_pem, expected_sender=None) -> bytes` — the recipient's side of integrity + decryption. Verifies the sender's cert and signature, unwraps the AES key, decrypts the ciphertext, returns plaintext. Any verification failure raises `CryptoError`/`AuthError`; file is **never written** on failure.

## Why this matters
This is where zero-trust pays off: the recipient does NOT trust the server. The server could have been compromised and swapped certs, signatures, or ciphertext bytes — this function catches all of that. If it returns plaintext, the recipient has a cryptographic guarantee that the bytes came from the named sender, intact, addressed to them.

## Dependencies
- **Blocked by:** #11a (`unwrap_aes_key`), #11b (`verify_origin_struct`), #17 (provides the payload to verify).
- **Used by:** #17 client side (calls this between recv and write-to-disk), #23 (integration test).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/client/download.py` | Add `verify_and_decrypt_download(...)` function. Used by `download_file` from #17. |
| `zerotrust/tests/test_decrypt_verify.py` | **NEW** — 6+ negative paths covering every tampering vector. |

## Frozen helpers you MUST use
```python
from zerotrust.ca.cert import verify_certificate
from zerotrust.common.crypto_primitives import aes_gcm_decrypt
from zerotrust.common.exceptions import AuthError, CryptoError
from zerotrust.common.key_wrap import unwrap_aes_key
from zerotrust.common.origin import verify_origin_struct
```

## Verification order (FAIL CLOSED at every step)
```python
def verify_and_decrypt_download(payload, my_priv_pem, my_password, ca_pubkey_pem,
                                 expected_sender=None):
    # 1. Verify sender's cert against the CA trust anchor.
    sender_cert = payload["sender_cert"]
    expected = expected_sender or payload["sender_id"]
    if not verify_certificate(sender_cert, ca_pubkey_pem, expected_subject=expected):
        raise AuthError("sender cert failed verification")

    # 2. Recompute the canonical origin struct AND verify the signature.
    sig = base64.b64decode(payload["sender_signature"], validate=True)
    if not verify_origin_struct(
        sender_cert,
        sig,
        sender=payload["sender_id"],
        recipient=my_username,
        file_id=payload["file_id"],
        ciphertext_sha256=hashlib.sha256(ct).hexdigest(),
        wrapped_key_sha256=hashlib.sha256(wrapped).hexdigest(),
        timestamp=payload["timestamp"],
        expiration=payload["expiration"],
    ):
        raise AuthError("origin signature invalid")

    # 3. Unwrap the AES key with OUR private key (RSA-OAEP).
    aes_key = unwrap_aes_key(my_priv_pem, my_password, wrapped)

    # 4. Decrypt with the recomputed AAD. AES-GCM auth tag catches any
    #    tampering of ciphertext OR aad (e.g. server swapping recipient).
    aad = f"{payload['file_id']}|{payload['sender_id']}|{my_username}".encode()
    return aes_gcm_decrypt(aes_key, nonce, ct, aad)
```

## Acceptance criteria
- [ ] Happy path: Alice uploads to Bob → Bob's `verify_and_decrypt_download` returns plaintext bit-identical to original.
- [ ] Sender cert from wrong CA → `AuthError`. Returns BEFORE unwrap_aes_key (cheap reject first).
- [ ] Sender cert subject `"alice"` but `expected_sender="charlie"` → `AuthError`.
- [ ] Signature tampered (1-byte flip) → `AuthError`.
- [ ] Any of the 7 origin-struct fields tampered between sign and verify → `AuthError`.
- [ ] AAD recipient field tampered (e.g. server reroutes Alice→Bob's file to Carol's inbox) → `CryptoError` from AES-GCM tag check.
- [ ] Ciphertext bit-flip → `CryptoError`.
- [ ] On **any** failure, the function raises BEFORE returning plaintext. No partial bytes leak.

## Required tests
- Happy: roundtrip with real keys.
- Sender cert tampered: replace `sender_cert["subject"]` with `"mallory"` → AuthError.
- Sender cert from wrong CA: build a cert with a second CA → AuthError.
- Subject pinning: pass `expected_sender="carol"` against an alice-signed package → AuthError.
- Signature 1-byte flip → AuthError.
- Each of the 7 canonical fields tampered (parametrize) → AuthError.
- Recipient swap: build AAD with wrong recipient → CryptoError from `aes_gcm_decrypt`.
- 1-byte ciphertext flip → CryptoError.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** decrypt before verifying. The verify-first / decrypt-last order is what gives us "fail closed without revealing key state". A timing side-channel between cert-verify and decrypt is bad enough; doing decrypt first leaks via error type.
- ❌ **DO NOT** use `cryptography.x509`. The `sender_cert` payload is the project's custom JSON cert format. Pass it directly to `verify_certificate(cert_dict, ca_pem, expected_subject=...)`.
- ❌ **DO NOT** roll your own canonical string for signature input. Use `zerotrust.common.origin.verify_origin_struct`, which internally uses `canonical_json` so client and server agree byte-for-byte. **Past mistake (#13):** `canonical_str = f"{sender}|{recipient}|..."` — wrong, no canonical encoding, doesn't match Turgut's sender side.
- ❌ **DO NOT** ignore the AAD. The whole point of AES-GCM is the auth tag binding context; if you forget to pass AAD, recipient swap attacks succeed silently.
- ❌ **DO NOT** print or log `aes_key`, `plaintext`, or the unwrapped pre-master.
- ❌ **DO NOT** wrap `unwrap_aes_key` failure in a generic `Exception` and continue. Let `CryptoError` propagate; the caller turns it into a user-facing `AUTH_FAILED`.

## References
- ARCHITECTURE.md §7.6 (signed origin struct — the 7 fields)
- ARCHITECTURE.md §7.7 (AAD format: `f"{file_id}|{sender}|{recipient}"`)
- ARCHITECTURE.md §8 (file lifecycle — recipient verify + decrypt)
