## Goal
Build `sign_origin_struct(sender_priv, password, *, sender, recipient, file_id, ciphertext_sha256, wrapped_key_sha256, timestamp, expiration) -> bytes` (returns the RSA-PSS signature) and `verify_origin_struct(sender_cert, signature, **same_fields) -> bool`.

## Why this matters
The server **cannot read the ciphertext** but **must verify** that Alice (the sender) really sent this exact (ciphertext + wrapped_key + routing) bundle. Without the origin signature, a malicious sender could repudiate ("I never sent that"), OR the server could swap ciphertexts between rows and remain undetectable.

Binding **both** `ciphertext_sha256` AND `wrapped_key_sha256` is the key trick: the server can't even substitute the wrapped key alone.

## Dependencies
- **Pairs tightly with:** #13 (server side calls `verify_origin_struct` on every UPLOAD_REQUEST). Coordinate field naming so both sides recompute exactly the same canonical JSON.
- **Blocked by:** none. You can implement on top of M1 primitives.
- **Used by:** #12 (upload sends signature), #18 (recipient verifies before trusting decrypted file).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/common/origin.py` | **NEW** — sign / verify helpers. |
| `zerotrust/tests/test_origin.py` | **NEW** — happy + every-field-tamper covered. |

## Canonical struct (ARCHITECTURE.md §7.6 — FROZEN)
```python
from zerotrust.common.canonical import canonical_json

def _build_canonical(*, sender, recipient, file_id,
                     ciphertext_sha256, wrapped_key_sha256,
                     timestamp, expiration) -> bytes:
    return canonical_json({
        "sender":             sender,
        "recipient":          recipient,
        "file_id":            file_id,
        "ciphertext_sha256":  ciphertext_sha256,   # hex string
        "wrapped_key_sha256": wrapped_key_sha256,  # hex string
        "timestamp":          timestamp,            # unix seconds, int
        "expiration":         expiration,           # unix seconds, int
    })
```

`canonical_json` (already in M1) does `sort_keys=True, separators=(",", ":")`. **Both sides MUST use this helper.** Anything else (whitespace, ordering) breaks the signature.

## Implementation steps
1. Build canonical bytes (function above).
2. Sign with `rsa_sign(sender_priv, password, canonical)`.
3. Server-side verify: recompute `canonical` from the SAME field values (received in payload), then `rsa_verify(sender_cert["public_key_pem"].encode(), canonical, signature)`.
4. Return / propagate `bool`. Fail-closed.

## Acceptance criteria
- [ ] Sign with sender's key → server verifies True.
- [ ] Tamper ANY ONE of the 7 fields between sign and verify → False. Test all 7 explicitly.
- [ ] Tamper signature byte → False.
- [ ] Reordering keys in the dict before signing does NOT affect the signature (canonical JSON is order-independent on input).

## Required tests
Parametrised on field name — flip each field, expect False:

```python
@pytest.mark.parametrize("field", [
    "sender", "recipient", "file_id",
    "ciphertext_sha256", "wrapped_key_sha256",
    "timestamp", "expiration",
])
def test_tamper_any_field_invalidates(field, ...):
    fields = baseline.copy()
    sig = sign_origin_struct(alice_priv, ALICE_PASSWORD, **fields)
    fields[field] = "tampered"   # or +1 for ints
    assert verify_origin_struct(alice_cert, sig, **fields) is False
```

## Pitfalls
- Do NOT add or remove fields without coordinating across #12, #13, #18 AND updating ARCHITECTURE.md §7.6.
- Do NOT use `json.dumps(...)` without `sort_keys=True, separators=(",", ":")` — use `canonical_json`. The frozen `check_frozen_signatures.py` doesn't enforce this; humans do.
- `ciphertext_sha256` and `wrapped_key_sha256` are hex strings (lowercase), not raw bytes. Decide and stick with it. (Hex is preferred for JSON portability.)
- Sign the canonical **bytes**, not the dict. RSA-PSS works on bytes only.

## References
- ARCHITECTURE.md §7.6 (Signed File-Origin Struct)
- ARCHITECTURE.md §2 (RSA-PSS for signatures)
- AI.md §2 (Canonical JSON for Signing)
