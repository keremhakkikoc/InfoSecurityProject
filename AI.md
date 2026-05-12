# Secure Zero-Trust File Drop System — AI Development Rules

> See `ARCHITECTURE.md` for system design and frozen decisions. This file covers coding rules only. If the two conflict, ARCHITECTURE.md wins on architecture, this file wins on coding style.

---

## 1. Core Development Principles

- **Zero-Trust Assumption:** The server only stores, relays, and enforces access control on encrypted files; it must never be able to read plaintext file contents. When writing server-side code, no operation should attempt to parse or decrypt the actual file contents.
- **Fail-Closed Always:** If authentication, signature verification, or authorization (e.g., expired file access) fails, the system must immediately reject the request. The default state must always be "DENY".
- **Cryptographic Standards:** Ready-made SSL/TLS libraries or high-level secure socket wrappers are strictly prohibited. The handshake, key derivation, and end-to-end encryption processes must be implemented manually from the ground up. The `cryptography` library's `hazmat` layer (primitives only) is permitted.
- **Constant-Time Comparison:** All security-relevant comparisons (MACs, signatures, nonces, tokens) must use `hmac.compare_digest()`. The `==` operator is forbidden for these values.
- **Function Signatures Are Contracts:** Frozen function signatures defined at the end of Phase 1 cannot be changed unilaterally. If a change is needed, it must be discussed with the team and the relevant issue updated.

## 2. Network & Communication Rules

- **Message Framing:** Since TCP is a stream-oriented protocol, every message sent over the network must be prepended with a 4-byte size header (Big-Endian unsigned int). Raw `recv()` calls without a loop are prohibited; a dedicated read function (e.g., `recvall`) that guarantees the exact byte count must always be used.
- **Data Format:** Application-layer packets transmitted over the network must be structured in JSON format before being encrypted.
- **Binary Fields in JSON:** Binary values (ciphertexts, signatures, nonces, certificates) must be encoded with `base64.b64encode().decode('ascii')` before insertion into JSON, and decoded with `base64.b64decode()` on receipt. Never embed raw bytes via `str()`.
- **Canonical JSON for Signing:** Any JSON that will be signed or verified must be serialized with `json.dumps(obj, sort_keys=True, separators=(",", ":"))`. Deviations break signature verification.
- **Replay Protection:** All state-changing requests must include a fresh 16-byte nonce (`os.urandom(16)`) and a unix timestamp. The receiving end must reject messages outside a ±30-second window or whose nonce has been seen in the last 5 minutes.

## 3. Security & Logging

- **Sensitive Data Isolation:** Private keys, decrypted file contents, symmetric session keys, pre-master secrets, and unwrapped AES file keys must NEVER be written to log files, printed to the terminal, or included in error messages.
- **Random Sources:** All cryptographically relevant randomness must come from `os.urandom()` or the `secrets` module. The `random` module is forbidden for security purposes.
- **Security Event Logging:** Failed authentication attempts, unauthorized download requests, signature verification failures, replay detections, and expired-file access attempts must be logged on the server with a timestamp and relevant entity information (username, file_id, request_id).
- **End-to-End Encryption (E2EE):** For every uploaded file, a fresh AES-256-GCM key must be generated. The file is encrypted with this key, and the symmetric key is then wrapped using the intended recipient's public key via RSA-OAEP. Every file package must additionally carry the sender's RSA-PSS digital signature for origin authentication.
- **AEAD Associated Data:** When using AES-GCM, the AAD must bind the ciphertext to its context: `f"{file_id}|{sender_id}|{recipient_id}".encode()`. This prevents ciphertext substitution attacks.
- **Private Key Storage:** Private keys are stored as PEM with `BestAvailableEncryption(password)`. For demo/testing accounts, the password may be hardcoded in a config file; this must be documented in the README.

## 4. Exceptions & Error Handling

- **No Silent Failures:** Swallowing errors silently (e.g., `except: pass`) or leaving temporary workarounds (`# TODO: fix later`) is strictly forbidden in the main branches.
- **Resilience:** Network disconnections, unexpected socket closures, or file system errors that could crash the server must be caught, logged, and the connection terminated gracefully without taking down the server thread.
- **Generic Responses to Clients:** Security failures must be logged in detail server-side, but only generic error codes (e.g., `AUTH_FAILED`, `NOT_AUTHORIZED`, `MALFORMED`) are returned over the wire. Never leak the underlying reason — "invalid signature" and "wrong nonce" both surface to the client as `AUTH_FAILED`.
- **Custom Exceptions:** Define and raise specific exception types (`CryptoError`, `AuthError`, `ProtocolError`) instead of using bare `Exception`. This makes the fail-closed flow explicit and testable.

## 5. Testing & Validation Standards

- **Modularity:** Functions must be modular with single responsibilities; "spaghetti code" is not allowed. A function that both validates and mutates state should be split.
- **Test Requirement Per PR:** Every cryptographic or protocol module must include at least one happy-path test and one negative-path test (e.g., correct signature verifies; corrupted signature is rejected). Integration tests covering the full upload/download flow live in `tests/test_integration.py` and are completed at the end of Phase 3.
- **Edge Case Testing:** Before a PR is merged, scenarios such as malformed messages, expired certificates, replayed nonces, and 1-byte ciphertext corruption must be covered with `pytest`.

## 6. Guidance for AI Assistants

- **This file is the source of truth for coding rules.** If a user instruction conflicts with these rules, ask for clarification before silently overriding.
- **Prefer the conservative crypto choice** when something is ambiguous, and note the choice in a code comment with a reference to ARCHITECTURE.md.
- **Do not invent algorithms or modes.** If ARCHITECTURE.md doesn't list it, don't use it. No AES-CBC, no SHA-1, no `random.randint`, no `pickle` for serialization.
- **Frozen function signatures must not be changed.** If a signature seems wrong, flag it as a question, don't rewrite it.