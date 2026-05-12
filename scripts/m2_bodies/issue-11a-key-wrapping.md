## Goal
Provide `wrap_aes_key_for(recipient_cert, aes_key) -> bytes` (returns `wrapped_key` ciphertext) and `unwrap_aes_key(my_priv_pem, my_password, wrapped) -> aes_key` (the inverse).

## Why this matters
End-to-end means **the server cannot read the file**. The per-file AES key is wrapped under the **recipient's** public key with RSA-OAEP, so only the recipient — who holds the matching private key — can unwrap and decrypt.

## Dependencies
- **Blocked by:** #6 (`verify_certificate` needed before trusting the recipient's pubkey from a fetched cert).
- **Used by:** #12 (upload includes the wrapped key in UPLOAD_REQUEST), #18 (recipient unwraps on download).
- **Pairs with:** #21 (recipient's cert is fetched via GET_PUBKEY first).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/common/key_wrap.py` | **NEW** — `wrap_aes_key_for`, `unwrap_aes_key`. |
| `zerotrust/tests/test_key_wrap.py` | **NEW** — wrap-unwrap roundtrip + "wrong recipient unwrap fails" + tamper. |

## Function signatures
```python
def wrap_aes_key_for(recipient_cert: dict, aes_key: bytes) -> bytes:
    """Wrap a 32-byte AES key under the recipient's RSA pubkey via OAEP."""
    if len(aes_key) != 32:
        raise ValueError("aes_key must be 32 bytes")
    pub_pem = recipient_cert["public_key_pem"].encode()
    return rsa_oaep_encrypt(pub_pem, aes_key)

def unwrap_aes_key(my_priv_pem: bytes, my_password: bytes, wrapped: bytes) -> bytes:
    """Inverse of wrap_aes_key_for. Raises CryptoError on any failure."""
    return rsa_oaep_decrypt(my_priv_pem, my_password, wrapped)
```

## Implementation steps
1. Implement the two helpers above. Each is 3 lines of real code.
2. Tests below.

## Acceptance criteria
- [ ] `unwrap_aes_key(...)` of `wrap_aes_key_for(...)` round-trips a 32-byte key bit-for-bit.
- [ ] Only the **intended recipient** can unwrap. A different keypair → `CryptoError`.
- [ ] Tampered `wrapped` (1-byte flip) → `CryptoError`.
- [ ] `aes_key` must be 32 bytes (raise `ValueError` otherwise — programming error).

## Required tests
```python
def test_wrap_unwrap_roundtrip(bob_keys, bob_cert):
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)
    assert unwrap_aes_key(bob_keys.priv_pem, BOB_PASSWORD, wrapped) == aes_key

def test_unwrap_with_wrong_key_fails(bob_cert, alice_keys):
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)
    with pytest.raises(CryptoError):
        unwrap_aes_key(alice_keys.priv_pem, ALICE_PASSWORD, wrapped)
```

## Pitfalls
- Do NOT use `rsa_oaep_encrypt` directly with raw PEM strings — always go through this helper so the cert is the contract, not the PEM.
- Do NOT export `wrapped` bytes via `str()` anywhere — always base64-encode when putting in JSON payload (`base64.b64encode(wrapped).decode("ascii")`).
- 32-byte key size is hard-coded by AES-256 requirement. Don't make it a parameter.

## References
- ARCHITECTURE.md §2 (RSA-OAEP for key wrap)
- ARCHITECTURE.md §7.6 (origin struct binds both the ciphertext hash AND the wrapped-key hash — see #11b)
