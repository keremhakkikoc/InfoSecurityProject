## Goal
Extend `verify_certificate(cert, ca_pubkey_pem)` so it can also enforce **subject match** — the third check in ARCHITECTURE.md §3.4.

## Why this matters
A cert can be valid (CA-signed, in date) but be the **wrong person's** cert. During the handshake, Alice presents her cert; the server must verify it was issued **to "alice"**, not to anyone-with-a-valid-cert. Subject pinning prevents identity-substitution attacks.

## Dependencies
- **Blocks:** #7 (PoP — needs to know whose cert), #8 (session key — uses verified peer cert), #13 (server signature verification), #18 (recipient verification).
- **Blocked by:** none.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/ca/cert.py` | Add optional `expected_subject` parameter to `verify_certificate`. Default `None` = subject not checked. |
| `scripts/check_frozen_signatures.py` | Update the EXPECTED entry for `verify_certificate`. |
| `ARCHITECTURE.md` §10.1 | Update the frozen signature line. |
| `zerotrust/tests/test_ca.py` | Add two tests: subject-match success, subject-mismatch failure. |

## Frozen signature change (backwards-compatible)
```python
# common/ca/cert.py
def verify_certificate(
    cert: dict,
    ca_pubkey_pem: bytes,
    expected_subject: str | None = None,    # NEW
) -> bool:
    ...
```

The default value of `None` keeps every existing call site working. **Update EXPECTED and ARCHITECTURE.md in the SAME PR** or CI will fail.

## Implementation steps
1. Keep all current checks intact (signature, valid_from/until).
2. After the signature check passes, if `expected_subject is not None`, compare `cert["subject"] == expected_subject`. Use plain `==` here — it's a public string, no timing side channel.
3. Any failure → return `False`. **Never raise.**
4. Update `scripts/check_frozen_signatures.py` EXPECTED entry and `ARCHITECTURE.md` §10.1.

## Acceptance criteria
- [ ] `verify_certificate(cert, ca_pub)` (no subject arg) behaves exactly as before — all existing tests pass.
- [ ] `verify_certificate(cert, ca_pub, expected_subject="alice")` returns `True` when subject matches.
- [ ] Same call with `expected_subject="mallory"` returns `False` on Alice's cert.
- [ ] `python scripts/check_frozen_signatures.py` passes (frozen contract updated).
- [ ] `make ci` green.

## Required tests
```python
def test_verify_with_matching_subject(ca_keys, user_keys):
    ca_priv, ca_pub = ca_keys
    _, pub = user_keys
    cert = cert_mod.issue_certificate("alice", pub, ca_priv, PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub, expected_subject="alice") is True

def test_verify_with_mismatched_subject(ca_keys, user_keys):
    ca_priv, ca_pub = ca_keys
    _, pub = user_keys
    cert = cert_mod.issue_certificate("alice", pub, ca_priv, PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub, expected_subject="mallory") is False
```

## Pitfalls
- Do NOT change the signature in a non-backwards-compatible way (e.g., positional `expected_subject`). Default `None` is mandatory.
- Do NOT use `hmac.compare_digest` for subject strings — they're public, not secrets. Constant-time compare is for MACs/signatures, not identifiers.
- Do NOT forget to also update `scripts/check_frozen_signatures.py` EXPECTED — otherwise the next CI run on `main` goes red.

## References
- ARCHITECTURE.md §3.4 (Verification, 3 steps)
- ARCHITECTURE.md §10.1 (Frozen signatures)
