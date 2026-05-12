# ARCHITECTURE — Secure Zero-Trust File Drop System

> **Status:** Frozen at Phase 1. Deviations require team consensus and an issue update.
> **Audience:** Developers (humans + AI assistants). This document is the source of truth for system-level decisions. If `AI.md` and this file conflict, this file wins on architecture; `AI.md` wins on coding rules.

---

## 1. System Components

Three logical entities, all written in Python:

| Component | Role |
|---|---|
| **CA** | Issues and signs certificates. Offline tool, runs as CLI. |
| **Server** | Stores encrypted files, enforces access control, relays public keys. Cannot read plaintext. |
| **Client** | Uploads encrypted files for other users, downloads files addressed to itself. |

**Trust model:** Clients trust the CA's public key (shipped manually as `ca_cert.json`). Clients do NOT trust the server beyond what CA signatures guarantee.

---

## 2. Cryptographic Choices (Frozen)

| Purpose | Algorithm |
|---|---|
| Asymmetric (signatures, key wrap, session establishment) | RSA-2048 |
| Signature padding | RSA-PSS (SHA-256, MGF1, salt length = digest length) |
| Key wrapping & session secret transport | RSA-OAEP (SHA-256, MGF1) |
| Symmetric encryption (file + channel) | AES-256-GCM |
| Key derivation | HKDF-SHA256 |
| Hash | SHA-256 |
| Random source | `os.urandom()` / `secrets` module only |

**Rationale:** RSA chosen over ECC to avoid maintaining two crypto stacks. AES-GCM provides authenticated encryption, eliminating the need for separate HMAC. All choices are supported by Python's `cryptography` library.

**Forbidden:**
- `ssl` module, OpenSSL wrappers, Paramiko, or any pre-built secure-channel library.
- `random` module for any security-relevant value.
- `==` for comparing MACs, signatures, or nonces — use `hmac.compare_digest()`.
- AES-CBC or AES-CTR (we standardized on GCM).

---

## 3. Identity & Certificates

### 3.1 Identity Model
A user is identified by a **username string** (e.g., `"alice"`), bound to a public key by a CA-signed certificate. The server enforces identity by verifying the certificate chain and proof-of-possession on every authenticated session.

### 3.2 Certificate Format (Custom JSON)
```json
{
  "subject": "alice",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "issuer": "CA",
  "valid_from": 1746360000,
  "valid_until": 1777896000,
  "serial": "uuid-v4-string",
  "signature": "base64-encoded-RSA-PSS-signature"
}
```

**Signing rule:** The signature covers `json.dumps(cert_without_signature, sort_keys=True, separators=(",", ":")).encode()`. The `sort_keys=True` and fixed separators are mandatory — any deviation breaks verification.

### 3.3 CA Bootstrap
The CA is a CLI tool. To issue a certificate:
```
python ca.py issue <username> <path_to_user_pubkey.pem>
```
This is a manual, demo-grade trust establishment. The CA's own keypair is generated once with `python ca.py init`.

### 3.4 Verification
A certificate is valid if and only if:
1. `valid_until > now() > valid_from`
2. The signature verifies against the CA's public key.
3. The `subject` matches the expected identity (when known in context).

---

## 4. Storage Layout

### 4.1 Server Side
```
server/
├── ca_trust/
│   └── ca_cert.json              # CA's own self-signed cert (trust anchor)
├── server_keys/
│   ├── server_private.pem        # password-encrypted PEM
│   └── server_cert.json          # CA-signed
├── storage/
│   ├── metadata.db               # SQLite, see schema below
│   ├── files/
│   │   └── <file_id>.bin         # AES-GCM ciphertext blobs
│   └── pubkeys/
│       └── <username>.json       # CA-signed certificates of registered users
└── logs/
    └── audit.log
```

### 4.2 Client Side
```
client_<username>/
├── ca_cert.json                  # CA trust anchor (manually distributed)
├── private.pem                   # password-encrypted PEM
├── cert.json                     # this user's CA-signed cert
├── config.json                   # { "server_host": "...", "server_port": ..., "username": "..." }
└── downloads/
    └── <original_filename>       # decrypted, verified files land here
```

### 4.3 Private Key Protection
Private keys are stored as PEM with `BestAvailableEncryption(password)`. For demo/testing, the password may be hardcoded in a config; this MUST be documented in the README.

---

## 5. SQLite Schema

```sql
CREATE TABLE files (
    file_id           TEXT PRIMARY KEY,        -- UUIDv4
    sender_id         TEXT NOT NULL,
    recipient_id      TEXT NOT NULL,
    upload_timestamp  INTEGER NOT NULL,        -- unix seconds
    expiration        INTEGER NOT NULL,        -- unix seconds
    status            TEXT NOT NULL,           -- 'pending' | 'downloaded' | 'expired' | 'revoked'
    ciphertext_path   TEXT NOT NULL,           -- relative to storage/files/
    ciphertext_sha256 TEXT NOT NULL,           -- hex
    wrapped_key       BLOB NOT NULL,           -- RSA-OAEP wrapped AES key
    aes_nonce         BLOB NOT NULL,           -- 12 bytes, GCM nonce
    aes_aad           BLOB NOT NULL,           -- associated data used during encryption
    sender_signature  BLOB NOT NULL,           -- RSA-PSS over signed struct (§7.3)
    sender_cert_json  TEXT NOT NULL            -- JSON-serialized sender certificate
);

CREATE INDEX idx_files_recipient ON files(recipient_id, status);

CREATE TABLE seen_nonces (
    nonce      BLOB PRIMARY KEY,
    seen_at    INTEGER NOT NULL                -- unix seconds, used for cleanup
);

CREATE INDEX idx_nonces_seen_at ON seen_nonces(seen_at);

CREATE TABLE acks (                            -- bonus: recipient acknowledgements
    file_id        TEXT PRIMARY KEY,
    ack_signature  BLOB NOT NULL,
    ack_timestamp  INTEGER NOT NULL
);
```

**Connection rule:** Each thread opens its own `sqlite3.Connection`. Do NOT share connections across threads.

---

## 6. Concurrency Model

- Server uses `threading` (one thread per accepted client connection).
- Each thread is fully independent: own socket, own DB connection, own session keys.
- Shared mutable state is limited to the SQLite database; SQLite handles locking internally.
- Background cleanup thread runs every 60 seconds to:
  - Delete `seen_nonces` rows older than 5 minutes.
  - Mark `files` rows as `'expired'` when `expiration < now()`.

---

## 7. Protocol

### 7.1 Wire Format
Every message on the wire:

```
[4-byte big-endian length] [JSON UTF-8 bytes]
```

Reads MUST use a `recvall(n)` helper that loops until exactly `n` bytes are received or the connection is closed.

### 7.2 Message Envelope
Every JSON message has this top-level structure:

```json
{
  "type": "MESSAGE_TYPE",
  "version": 1,
  "nonce": "base64-16-bytes",
  "timestamp": 1746360000,
  "request_id": "uuid-v4",
  "payload": { ... }
}
```

After session establishment (§7.4), the entire envelope (except a small unencrypted header for routing) is encrypted with the appropriate session key. Pre-handshake messages travel in plaintext but still carry nonces.

**Binary fields inside `payload`:** always base64-encoded strings.

### 7.3 Message Types

| Type | Direction | Purpose |
|---|---|---|
| `HELLO` | C→S, S→C | Exchange certificates and nonces |
| `KEY_EXCHANGE` | C→S | Encrypted pre-master secret (RSA-OAEP) |
| `AUTH_CHALLENGE` | S→C | Server sends nonce for client to sign |
| `AUTH_RESPONSE` | C→S | Client returns signature over nonce |
| `SESSION_OK` | S→C | Handshake complete |
| `GET_PUBKEY` | C→S | Request another user's certificate |
| `PUBKEY_RESPONSE` | S→C | CA-signed cert of the requested user |
| `UPLOAD_REQUEST` | C→S | Encrypted file package + signed metadata |
| `UPLOAD_ACK` | S→C | File accepted (or rejected with error code) |
| `LIST_PENDING` | C→S | Request list of files for me |
| `PENDING_LIST` | S→C | Array of pending file metadata |
| `DOWNLOAD_REQUEST` | C→S | Request a specific file by file_id |
| `DOWNLOAD_RESPONSE` | S→C | Encrypted file package |
| `DOWNLOAD_ACK` | C→S | (Bonus) Signed acknowledgement after successful decrypt+verify |
| `REVOKE_REQUEST` | C→S | (Bonus) Sender revokes a pending file |
| `ERROR` | either | Generic error with reason code |

### 7.4 Handshake Flow
```
Client                                                      Server
  |                                                            |
  |-- HELLO { client_cert, client_nonce_c } ----------------->|
  |<-- HELLO { server_cert, server_nonce_s } -----------------|
  |                                                            |
  |   [both sides verify peer cert against CA]                 |
  |                                                            |
  |-- KEY_EXCHANGE { RSA-OAEP(server_pk, pre_master) } ------>|
  |                                                            |
  |   [both derive: pre_master + nonce_c + nonce_s -> HKDF]    |
  |   [keys: c2s_key, s2c_key (32 bytes each)]                 |
  |                                                            |
  |<-- AUTH_CHALLENGE { auth_nonce } -- (encrypted s2c) -------|
  |-- AUTH_RESPONSE { sign(client_priv, auth_nonce            |
  |                        || transcript_hash) } -- (enc) --->|
  |                                                            |
  |   [server verifies signature with client cert pk]          |
  |   [if first: server may also do reverse PoP — see below]   |
  |                                                            |
  |<-- SESSION_OK -- (encrypted s2c) ---------------------------|
```

**Mutual proof-of-possession:** The server proves possession by signing a transcript hash that includes both nonces, returned inside `SESSION_OK`. The client verifies this before considering the session authenticated.

**Transcript hash:** `SHA-256(client_nonce_c || server_nonce_s || pre_master_ciphertext)`. Both sides bind the auth signatures to this value to defeat substitution attacks.

### 7.5 HKDF Derivation
```
salt   = client_nonce_c || server_nonce_s        (32 bytes)
ikm    = pre_master                               (32 bytes)
info   = b"zerotrust-v1"
okm    = HKDF-SHA256(ikm, salt, info, length=64)
c2s_key = okm[0:32]
s2c_key = okm[32:64]
```

### 7.6 Signed File-Origin Struct
The sender signs the following canonical JSON:

```python
canonical = json.dumps({
    "sender":            sender_id,
    "recipient":         recipient_id,
    "file_id":           file_id,
    "ciphertext_sha256": hex_digest,
    "wrapped_key_sha256": hex_digest,
    "timestamp":         unix_seconds,
    "expiration":        unix_seconds
}, sort_keys=True, separators=(",", ":")).encode()

signature = rsa_pss_sign(sender_private_key, canonical)
```

**Both** the ciphertext hash and the wrapped-key hash are bound, so the server cannot substitute either component.

### 7.7 AES-GCM Associated Data
For file encryption, AAD is:
```python
aad = f"{file_id}|{sender_id}|{recipient_id}".encode()
```
Decryption fails if any of these three are tampered with.

### 7.8 Replay Protection
Every `*_REQUEST` message is checked:
1. `abs(now() - msg.timestamp) <= 30` seconds → else reject as `STALE`.
2. `msg.nonce` not in `seen_nonces` → else reject as `REPLAY`.
3. On accept, insert into `seen_nonces`.

Cleanup thread deletes nonces older than 5 minutes (well outside the 30-second window).

### 7.9 Error Codes (Generic to Client, Detailed in Logs)
```
AUTH_FAILED, NOT_AUTHORIZED, NOT_FOUND, EXPIRED, REVOKED,
ALREADY_DOWNLOADED, REPLAY, STALE, MALFORMED, INTERNAL_ERROR
```
The client never receives the underlying reason (e.g., "invalid signature" vs "wrong nonce" both surface as `AUTH_FAILED`).

---

## 8. File Lifecycle

```
[upload]
  client encrypts file with fresh AES-GCM key
  client wraps AES key with recipient's RSA pubkey (OAEP)
  client signs the canonical struct (§7.6)
  client sends UPLOAD_REQUEST
  server verifies: sender cert (CA), sender PoP (session), signature, freshness
  server stores ciphertext + metadata, status='pending'

[list]
  recipient sends LIST_PENDING
  server returns rows where recipient_id=me AND status='pending' AND expiration > now()

[download]
  recipient sends DOWNLOAD_REQUEST { file_id }
  server checks: recipient match, status='pending', not expired, not revoked
  server returns DOWNLOAD_RESPONSE with full encrypted package
  recipient unwraps AES key, decrypts file, verifies signature
  recipient sends DOWNLOAD_ACK (bonus) — signed { file_id, "received", timestamp }
  server verifies ACK signature, updates status='downloaded'

[expiration]
  cleanup thread marks status='expired' when expiration < now()
  any access attempt on expired file → EXPIRED error, logged

[revocation] (bonus)
  sender sends REVOKE_REQUEST { file_id, signature_over_revoke_struct }
  server verifies sender owns the file and signature is valid
  if status still 'pending', set status='revoked'
  any download attempt on revoked file → REVOKED error, logged
```

---

## 9. Logging

- Single logger named `zerotrust`, configured in `common/logger.py`.
- Format: `%(asctime)s | %(levelname)s | %(name)s | %(message)s`
- File: `server/logs/audit.log` (server) / `client_<user>/logs/client.log` (client).
- Levels:
  - `INFO` — connection established, upload accepted, download served, ACK received
  - `WARNING` — auth failures, expired access, unauthorized download attempts, replay detected
  - `ERROR` — signature verification failures, malformed messages, internal errors
- **Never logged:** private keys, plaintext file contents, session keys, pre-master secrets, decrypted nonces of long-lived secrets.
- **Logged but redacted:** certificate fingerprints (first 16 hex chars), file_ids, usernames, request_ids, timestamps.

---

## 10. Module Layout & Function Contracts

```
zerotrust/
├── ARCHITECTURE.md            (this file)
├── AI.md
├── README.md
├── requirements.txt
├── common/
│   ├── __init__.py
│   ├── logger.py
│   ├── protocol.py            # message envelope, types, framing
│   ├── crypto_primitives.py   # thin wrappers over cryptography lib
│   └── canonical.py           # canonical JSON helpers
├── ca/
│   ├── __init__.py
│   ├── ca.py                  # CLI entry point
│   └── cert.py                # certificate issue/verify
├── server/
│   ├── __init__.py
│   ├── main.py                # entry point
│   ├── handler.py             # per-connection thread logic
│   ├── handshake.py
│   ├── store.py               # SQLite access
│   └── replay.py              # nonce cache
├── client/
│   ├── __init__.py
│   ├── cli.py                 # entry point
│   ├── handshake.py
│   ├── upload.py
│   └── download.py
└── tests/
    ├── test_crypto.py
    ├── test_handshake.py
    ├── test_upload_download.py
    └── test_integration.py    # the demo-script flow
```

### 10.1 Frozen Function Signatures (Phase 1 → Phase 2 contract)

These signatures are the contract between issues. Implementations land in Phase 2; signatures land at end of Phase 1.

```python
# common/crypto_primitives.py
def generate_rsa_keypair(password: bytes) -> tuple[bytes, bytes]: ...
    # returns (private_pem_encrypted, public_pem)
    # password is required and non-empty (PEM is always BestAvailableEncryption)

def rsa_sign(private_pem: bytes, password: bytes, data: bytes) -> bytes: ...
def rsa_verify(public_pem: bytes, data: bytes, signature: bytes) -> bool: ...
def rsa_oaep_encrypt(public_pem: bytes, data: bytes) -> bytes: ...
def rsa_oaep_decrypt(private_pem: bytes, password: bytes, data: bytes) -> bytes: ...

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]: ...
    # returns (nonce_12b, ciphertext_with_tag)
def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...
    # raises CryptoError on auth failure

def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int, extra: str = "") -> bytes: ...

# ca/cert.py
def issue_certificate(subject: str, subject_pubkey_pem: bytes,
                      ca_priv_pem: bytes, ca_password: bytes,
                      validity_days: int = 365) -> dict: ...
def verify_certificate(cert: dict, ca_pubkey_pem: bytes) -> bool: ...
    # returns True iff signature valid AND not expired

# common/protocol.py
def pack_message(msg: dict) -> bytes: ...    # 4-byte length + JSON
def recv_message(sock) -> dict: ...           # blocking, uses recvall
def make_envelope(msg_type: str, payload: dict) -> dict: ...
    # adds version, nonce, timestamp, request_id

# server/replay.py
def check_and_record(conn, nonce: bytes, timestamp: int) -> bool: ...
    # True if accepted, False if STALE or REPLAY
```

**Rule:** Once Phase 1 ships these signatures (with `NotImplementedError` bodies), they are frozen. Changes require an issue update and team notification.

---

## 11. Bonus Features in Scope

The team commits to these bonuses:
- **Revocation** (sender can revoke a pending file).
- **One-time download** (file consumed only after recipient ACK).
- **Recipient acknowledgement** (signed ACK after decrypt+verify).

Out of scope (may be added if time permits):
- Containerization, encrypted notes, large-file chunking, confidential metadata.

---

## 12. Out-of-Scope / Known Limitations

These are deliberate simplifications, to be discussed in the Security Analysis section of the README:
- The CA is offline and trust is bootstrapped manually (no revocation lists, no chain depth > 1).
- The server learns sender, recipient, file size, and timing — full metadata privacy is not provided.
- Private key passwords for demo accounts are stored in config files; production use would require interactive prompts or OS keychain integration.
- No protection against a malicious server colluding with a compromised client to perform traffic analysis.
- No forward secrecy: compromise of a long-term RSA private key compromises past sessions. (Would require ECDHE; out of scope by RSA-only decision.)

---

## 13. Phase Boundaries

- **Phase 1 (solo):** This document, frozen function signatures with `NotImplementedError`, working CA, working TCP framing, working RSA keygen. Issues #1–#4.
- **Phase 2 (parallel):** Handshake + Upload. Issues #5–#14, #21, #22a. PRs against `develop`.
- **Phase 3 (parallel):** Download + hardening + bonus + integration test. Issues #15–#20, #22b, #23, plus selected bonuses.

End of Phase 1 = `develop` branch boots, all Phase 2 issues have unblocked function signatures to implement against.
