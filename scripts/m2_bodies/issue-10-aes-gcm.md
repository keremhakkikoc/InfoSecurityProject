## Goal
Build a single helper `encrypt_file_blob(plaintext, file_id, sender, recipient) -> (nonce, ciphertext, aes_key)` that wraps `aes_gcm_encrypt` with the correct AAD binding.

## Why this matters
AES-GCM **without** AAD lets the server (or an attacker who steals a row) swap ciphertexts between metadata rows: take Alice→Bob's ciphertext, paste it into Carol→Dave's row, the cipher still decrypts. The AAD `"{file_id}|{sender}|{recipient}"` makes the auth tag depend on the routing context, so any reuse breaks the tag.

## Dependencies
- **Blocked by:** none. The `aes_gcm_encrypt` primitive is already implemented in M1.
- **Used by:** #12 (upload), #18 (recipient decrypt).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/common/file_crypto.py` | **NEW** — `encrypt_file_blob` and its inverse `decrypt_file_blob`. |
| `zerotrust/tests/test_file_crypto.py` | **NEW** — happy + AAD mismatch + ciphertext tamper + wrong key. |

## Function signatures
```python
import os

def encrypt_file_blob(
    plaintext: bytes,
    file_id: str,
    sender: str,
    recipient: str,
) -> tuple[bytes, bytes, bytes]:
    """Return (nonce, ciphertext_with_tag, aes_key).

    aes_key is fresh per call (32 random bytes). Caller is responsible for
    wrapping it with the recipient's public key (see #11a).
    """
    aes_key = os.urandom(32)
    aad = f"{file_id}|{sender}|{recipient}".encode()
    nonce, ct = aes_gcm_encrypt(aes_key, plaintext, aad)
    return nonce, ct, aes_key

def decrypt_file_blob(
    aes_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    file_id: str,
    sender: str,
    recipient: str,
) -> bytes:
    """Return plaintext. Raises CryptoError on any AAD / ciphertext / key mismatch."""
    aad = f"{file_id}|{sender}|{recipient}".encode()
    return aes_gcm_decrypt(aes_key, nonce, ciphertext, aad)
```

## Implementation steps
1. Implement the two helpers above. They are 4–5 lines each.
2. Add the new module to imports where needed (M2 #12, M3 #18).
3. Tests cover the four bullets below.

## Acceptance criteria
- [ ] `decrypt_file_blob(encrypt_file_blob(...))` round-trips identical plaintext.
- [ ] Changing `recipient` between encrypt and decrypt → `CryptoError`.
- [ ] 1-byte flip in `ciphertext` → `CryptoError`.
- [ ] Wrong `aes_key` → `CryptoError`.
- [ ] `nonce` is 12 bytes; two calls produce different nonces (use `secrets`/`os.urandom`).

## Required tests
```python
def test_roundtrip():
    n, ct, k = encrypt_file_blob(b"hello", "file-1", "alice", "bob")
    assert decrypt_file_blob(k, n, ct, "file-1", "alice", "bob") == b"hello"

def test_aad_recipient_mismatch():
    n, ct, k = encrypt_file_blob(b"x", "file-1", "alice", "bob")
    with pytest.raises(CryptoError):
        decrypt_file_blob(k, n, ct, "file-1", "alice", "mallory")
```

## Pitfalls
- **Never** reuse an AES-GCM `(key, nonce)` pair. Since we generate a fresh key per file, you're safe by construction — but don't ever invent a "deterministic nonce" optimisation.
- AAD is bytes, not str. Use `.encode()`.
- Do NOT compress plaintext "to make ciphertext smaller" — CRIME-class attacks.
- Do NOT log the AES key, plaintext, or even the AAD with full identifiers — AI.md §3.

## References
- ARCHITECTURE.md §2 (AES-256-GCM)
- ARCHITECTURE.md §7.7 (AAD binding format)
- AI.md §3 (Sensitive Data Isolation)
