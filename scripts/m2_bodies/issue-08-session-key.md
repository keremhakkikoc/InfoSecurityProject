## Goal
Implement the full handshake state machine on both sides. End state: both peers hold the same `c2s_key` and `s2c_key` (32 bytes each), derived via HKDF from a pre-master Alice generated and OAEP-encrypted under the server's pubkey.

## Why this matters
This is the load-bearing piece of M2. Everything after this — encrypted upload, signed metadata, audit logging — assumes both sides agree on `c2s_key` / `s2c_key`. If this is wrong, **nothing** else can work. Treat it as the hardest hour-per-line code in the whole milestone.

## Dependencies
- **Blocks:** #5 handshake invocation, #9 CLI login, #12 upload (needs session keys), #13 server upload accept.
- **Blocked by:** #6 (cert verify) **and** #7 (PoP). Do NOT start coding the body until both land.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handshake.py` | `perform_server_handshake(sock, server_cert, server_priv_pem, server_password, ca_pubkey_pem) -> dict` |
| `zerotrust/client/handshake.py` | `perform_client_handshake(sock, client_cert, client_priv_pem, client_password, ca_pubkey_pem, expected_server_subject=None) -> dict` |
| `zerotrust/tests/test_handshake.py` | **NEW** — two threads, one runs server, one runs client, asserts session dict equality of key material. |

## Frozen contract (return shape)
```python
{
    "peer_subject":    "alice",          # str, from verified peer cert
    "peer_cert":        {...},           # dict, the full verified cert
    "c2s_key":          b"\x..." * 32,   # 32 bytes
    "s2c_key":          b"\x..." * 32,   # 32 bytes
    "transcript_hash":  b"\x..." * 32,   # 32 bytes
}
```

Phase 2/3 callers depend on **exactly** this shape.

## HKDF derivation (frozen by §7.5)
```python
from zerotrust.common.crypto_primitives import hkdf_derive
okm = hkdf_derive(
    ikm=pre_master,                  # 32 bytes
    salt=nonce_c + nonce_s,           # 32 bytes total
    info=b"zerotrust-v1",
    length=64,
)
c2s_key = okm[0:32]
s2c_key = okm[32:64]
```

## Implementation steps (server side)
1. **Recv HELLO** from client. Validate envelope with `protocol.validate_envelope`.
2. Load `client_cert` from payload. Call `verify_certificate(client_cert, ca_pub, expected_subject=None)` — we don't pin subject server-side, anyone CA-signed can connect. (Subject is recorded for downstream auth.)
3. **Send HELLO** with server cert + fresh `nonce_s` (16 bytes from `os.urandom`).
4. **Recv KEY_EXCHANGE.** Decrypt `pre_master_ct` with `rsa_oaep_decrypt(server_priv, server_password, ct)`. Wrong → `CryptoError` → close socket, log `AUTH_FAILED`.
5. Compute `transcript_hash` (per #7).
6. **Recv AUTH_RESPONSE.** Verify client's PoP signature (per #7). Fail-closed.
7. Derive keys via HKDF (above).
8. **Send SESSION_OK** containing server's own PoP signature over the transcript.
9. Return the session dict.

## Implementation steps (client side)
Symmetric. The client generates `pre_master = os.urandom(32)`, encrypts it with `rsa_oaep_encrypt(server_pub, pre_master)`, signs the transcript, sends, and verifies the server's PoP from SESSION_OK before considering the handshake live.

## Acceptance criteria
- [ ] Server and client both compute the **same** `c2s_key` and `s2c_key` (bit-for-bit identical).
- [ ] Wrong server password → `CryptoError`, socket closed, no key material returned.
- [ ] Tampered `pre_master_ct` (1 byte flip) → handshake fails on server side.
- [ ] Client gets a fake server cert (different CA) → verification fails, client aborts before sending pre-master.
- [ ] Session dict shape matches the frozen contract exactly.

## Required tests
* **Roundtrip:** spawn server thread on ephemeral port, run client in main thread, assert `server_state["c2s_key"] == client_state["c2s_key"]` and same for s2c.
* **Negative:** server uses wrong password → handshake fails, server logs `AUTH_FAILED`, client gets generic error.
* **Negative:** client presents an expired cert → server rejects in step 2 before any key material is exchanged.

## Pitfalls
- The HKDF `salt = nonce_c + nonce_s` order matters. BOTH sides must concatenate the same way. ARCHITECTURE.md §7.5 fixes the order.
- Do NOT log `pre_master`, `c2s_key`, `s2c_key`, or `transcript_hash`. Only fingerprints.
- `hkdf_derive(..., extra="")` — leave `extra` at its default unless you have a documented reason. We added that param but it's not actively used in M2.
- Use the protocol envelope for every message (`make_envelope` + `pack_message`). Don't roll your own JSON.
- Pre-handshake messages are **plaintext** (carrying certs). After SESSION_OK, every subsequent envelope is encrypted with `s2c_key` / `c2s_key`. M2 doesn't yet exercise post-handshake encrypted traffic — that's #12 / #13's job — but the keys live in the returned dict for them.

## References
- ARCHITECTURE.md §7.4 (Handshake Flow, the ladder diagram)
- ARCHITECTURE.md §7.5 (HKDF Derivation)
