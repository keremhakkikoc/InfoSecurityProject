## Goal
Implement **proof-of-possession (PoP)** signing and verification: each side proves it holds the private key matching the cert it just presented, by signing a transcript hash that binds both nonces.

## Why this matters
A cert alone proves nothing — anyone can copy Alice's cert (it's public). To prove they are **Alice**, the client must sign something fresh with Alice's private key. Same goes for the server. Without PoP, an attacker who steals Alice's cert (but not her private key) could impersonate her.

## Dependencies
- **Blocks:** #8 (session key needs both PoP signatures verified before promoting the session).
- **Blocked by:** #6 (you need verified peer cert before checking their PoP).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/common/crypto_primitives.py` | Already has `rsa_sign` / `rsa_verify`. **Don't change signatures.** You use them. |
| `zerotrust/server/handshake.py` | Add `_build_transcript_hash(nonce_c, nonce_s, pre_master_ciphertext) -> bytes` (private helper). |
| `zerotrust/client/handshake.py` | Same helper here too — or import from a `common/transcript.py` if you'd rather centralise. |
| `zerotrust/tests/test_pop.py` | **NEW** — happy, tampered nonce, tampered signature, swapped signer. |

## Transcript hash (frozen by ARCHITECTURE.md §7.4)
```python
import hashlib
def _build_transcript_hash(nonce_c: bytes, nonce_s: bytes,
                          pre_master_ct: bytes) -> bytes:
    """SHA-256 binding both nonces AND the OAEP-encrypted pre-master."""
    h = hashlib.sha256()
    h.update(nonce_c)        # 16 bytes
    h.update(nonce_s)        # 16 bytes
    h.update(pre_master_ct)  # variable, length-bound by RSA-2048
    return h.digest()
```

## Implementation steps
1. Build the transcript hash from `nonce_c || nonce_s || pre_master_ct`.
2. **Client side:** `rsa_sign(client_priv_pem, client_password, transcript_hash)` → put in `AUTH_RESPONSE`.
3. **Server side after `AUTH_RESPONSE`:** `rsa_verify(client_cert["public_key_pem"].encode(), transcript_hash, signature)`. Fail-closed.
4. **Server side in `SESSION_OK`:** sign the same transcript with server's private key. Client verifies before considering session live.
5. Any verification failure → close the socket, log `auth failure: <fingerprint>`, return generic `AUTH_FAILED` to peer.

## Acceptance criteria
- [ ] Correct PoP signature verifies on both sides.
- [ ] Tampering with `nonce_c`, `nonce_s`, OR `pre_master_ct` before verify → `rsa_verify` returns `False`.
- [ ] Tampering with the signature (1-byte flip) → `False`.
- [ ] Signing with a DIFFERENT private key (attacker forgery) → server's verify returns `False`.
- [ ] Server never raises — always returns False and logs a generic error.

## Required tests
- Happy: client signs transcript with its own key → server verifies True.
- Negative 1: tamper a single byte in `nonce_c` between sign and verify → False.
- Negative 2: tamper the signature itself → False.
- Negative 3: sign with key_A, present cert containing pubkey_B → False (this is the classic identity-substitution attack).

## Pitfalls
- Do NOT hash only the nonces and forget `pre_master_ct` — without binding the encrypted secret, an attacker can swap pre-masters across sessions.
- Do NOT sign the **plaintext** pre-master — sign its **ciphertext** (the OAEP output), so both sides can recompute the hash before the server has even decrypted. Spec is explicit.
- Do NOT log the signature itself or the transcript hash bytes — log only a fingerprint. AI.md §3.
- Remember: `rsa_verify` returns `bool`, never raises. Don't wrap it in try/except.

## References
- ARCHITECTURE.md §7.4 (Handshake Flow, Mutual PoP)
- ARCHITECTURE.md §2 (RSA-PSS for signatures)
- AI.md §3 (Sensitive Data Isolation — never log secrets)
