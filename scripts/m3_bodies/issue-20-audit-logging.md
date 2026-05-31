## Goal
Route every security-relevant event through `zerotrust.common.logger` with the right severity, including the sender/recipient/file_id and a fingerprint of any cert involved — but **never** including private keys, plaintext file contents, session keys, pre-master secrets, or unwrapped AES file keys.

## Why this matters
Two reasons. (1) For grading: ARCHITECTURE.md §9 explicitly lists what gets logged at INFO / WARNING / ERROR, and the assignment expects an audit log file the grader can inspect. (2) Sensitive-data isolation: a single careless `logger.debug(f"key={c2s_key}")` defeats every other defence we built. This issue is the one chance to grep the repo and make sure we never did that.

## Dependencies
- **Used by:** every other server-side handler (upload accept, download served, replay detected, auth failures).
- **Blocked by:** none. Touches finished modules.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/handler.py` | Replace any ad-hoc `print()` / `logger.error(f"...")` with the structured pattern below. |
| `zerotrust/server/handshake.py` | Same audit pattern at handshake start/end + every fail-closed path. |
| `zerotrust/common/logger.py` | Already has `get_logger` + `fingerprint`. If a missing redaction helper turns up, add it here. |
| `zerotrust/tests/test_audit_log.py` | **NEW** — assert no secrets leak. Driven by `caplog` + grep-style filter. |

## Severity matrix (ARCHITECTURE.md §9 — FROZEN)
| Level | Event |
|---|---|
| `INFO` | connection established, handshake complete, upload accepted, download served, ACK received |
| `WARNING` | auth failures, expired access, unauthorized download, replay detected |
| `ERROR` | signature verification failures, malformed messages, internal errors |

## Mandatory log fields
Every event line includes (at minimum):
- `event` — short identifier (e.g. `upload_accept`, `replay_reject`)
- `file_id` — when relevant
- `sender` / `recipient` / `peer_subject` — when relevant
- `request_id` — copied from the envelope's request_id
- `fp=<16-hex>` — `fingerprint(cert_pubkey_pem)` for any cert involved

## Forbidden log fields — NEVER appear in log output
- Private keys / PEM bytes
- Plaintext file contents
- `pre_master`, `c2s_key`, `s2c_key`, `transcript_hash` raw bytes
- Unwrapped AES file keys
- Full signatures (only the first 8 hex chars of a sha256 are OK)
- Passwords (CA password, user password, ZEROTRUST_*_PASSWORD env values)

## Acceptance criteria
- [ ] `grep -E '(BEGIN PRIVATE KEY|password=|c2s_key=|aes_key=|plaintext=)' server/logs/audit.log` returns NOTHING after running the full demo.
- [ ] Every UPLOAD_REQUEST accept logs `INFO event=upload_accept file_id=... sender=... recipient=... fp=...`.
- [ ] Every replay/stale/auth-fail logs at `WARNING` with the real reason (the client still got the generic code, the log is allowed to be detailed).
- [ ] Every signature verification failure logs at `ERROR`.
- [ ] Test asserts that even when we log a cert dict, only the `fingerprint(...)` (16 hex chars) is emitted, never the full `public_key_pem`.

## Required tests
- Run a happy upload → assert `INFO event=upload_accept` line exists with the right `file_id`.
- Run a forged upload → assert `ERROR` with `event=origin_sig_fail` AND that `payload["signature"]` raw bytes are absent from `caplog.text`.
- Run a replay → `WARNING event=replay_reject` with `nonce_fp` only, not the raw nonce.
- Scan the entire `caplog.text` after a full integration test (#23) with a regex matching the Forbidden list — must produce 0 matches.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** `logger.debug(f"session={session}")`. The session dict contains `c2s_key`, `s2c_key`, and the full peer cert. Log only `session["peer_subject"]` and `fingerprint(session["peer_cert"]["public_key_pem"].encode())`.
- ❌ **DO NOT** `print(...)` anywhere in production code paths. Use the named logger (`logging.getLogger(__name__)` is fine; the project's `get_logger` configures handler + format).
- ❌ **DO NOT** include the full signature bytes in any log line. The first 8 hex chars of `sha256(signature)` is plenty for correlation.
- ❌ **DO NOT** log the upload payload as a whole even after rejection — it contains the ciphertext and wrapped key. Log the **decision** (`event=upload_reject reason=stale`) and the IDs, not the bytes.
- ❌ **DO NOT** quote private-key paths in error messages sent to the wire. Server log can say "loaded /etc/.../server.pem"; the client must only see `INTERNAL_ERROR`.
- ❌ **DO NOT** assume that because a value is "just a fingerprint" it's safe — a fingerprint of a low-entropy value (e.g. the demo password) is still attackable. Fingerprint **only** high-entropy items (pubkeys, signatures, ciphertexts).

## References
- ARCHITECTURE.md §9 (logging spec — format, file paths, severity table)
