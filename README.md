# Secure Zero-Trust File Drop System

Implementation for **CSE 4057 Programming Assignment, Spring 2026**
(due 24 May 2026).

A custom application-layer protocol over raw TCP that lets one user drop an
encrypted file at a server for another user. The server stores the
ciphertext and metadata only — it can never read plaintext file contents.
SSL/TLS libraries are deliberately not used; the handshake, key derivation,
and end-to-end encryption are implemented from scratch on top of the
`cryptography` library's primitives.

> See `ARCHITECTURE.md` for the system design (frozen at end of Phase 1)
> and `AI.md` for coding rules.

## Team Members

- Alp Büyükköse— Team Leader
- Kerem Hakkı Koç
- Turgut Köroğlu

## Project Status

| Milestone | Status |
|---|---|
| **M1 — Foundation (solo)** | ✅ Complete |
| M2 — Handshake + Upload (parallel) | ✅ Complete (this PR) |
| M3 — Download + Hardening + Bonus | ⚪ Not started |

### What M1 ships

- `ARCHITECTURE.md` — frozen system design, including the custom JSON
  certificate format (§3.2), the wire protocol (§7), the SQLite schema
  (§5), and the **frozen function signatures** that Phase 2/3 issues
  implement against (§10.1).
- `AI.md` — coding rules (zero-trust, fail-closed, constant-time
  comparison, no SSL libs).
- Working **CA module** with a CLI (`init`, `issue <username>`, `verify`).
- Working **TCP framing + envelope** in `zerotrust/common/protocol.py`.
- Working **crypto primitives** (RSA keygen with encrypted PEM, RSA-PSS
  sign/verify, RSA-OAEP wrap/unwrap, AES-256-GCM, HKDF-SHA256) in
  `zerotrust/common/crypto_primitives.py`.
- Working **replay nonce cache** (`zerotrust/server/replay.py`).
- Frozen `NotImplementedError` stubs for every Phase 2/3 entry point so
  parallel development is unblocked.
- 57 pytest tests covering happy path + negative path for every M1 module.

## Module Layout

```
zerotrust/
├── common/
│   ├── crypto_primitives.py    # RSA, AES-GCM, HKDF wrappers
│   ├── protocol.py             # length-prefixed JSON framing + envelope
│   ├── canonical.py            # canonical JSON for signing
│   ├── logger.py               # logger setup, fingerprint redaction
│   └── exceptions.py           # CryptoError / AuthError / ProtocolError
├── ca/
│   ├── cert.py                 # issue_certificate / verify_certificate
│   └── ca.py                   # CLI: init / issue / verify
├── server/
│   ├── replay.py               # ✅ implemented (check_and_record + purge)
│   ├── store.py                # 🟡 stub — Phase 2 issue #14
│   ├── handshake.py            # 🟡 stub — Phase 2 issue #8
│   ├── handler.py              # 🟡 stub — Phase 2 issue #5
│   └── main.py                 # 🟡 stub — Phase 2 issue #5
├── client/
│   ├── cli.py                  # 🟡 stub — Phase 2 issue #9
│   ├── handshake.py            # 🟡 stub — Phase 2 issue #8
│   ├── upload.py               # 🟡 stub — Phase 2 issue #12
│   └── download.py             # 🟡 stub — Phase 3 issue #17
└── tests/
    ├── test_protocol.py
    ├── test_crypto.py
    ├── test_canonical.py
    ├── test_ca.py
    └── test_replay.py
```

The `legacy/` directory contains the pre-architecture X.509 prototype, kept
for reference; nothing in the active package imports from it.

## How to Run

### 1. Setup

```bash
python -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the test suite

```bash
pytest
```

All 57 tests should pass in under 2 seconds.

### 3. Bootstrap the CA and issue user certificates

```bash
# Initialise the CA (writes ca_data/{ca_private.pem, ca_public.pem, ca_cert.json})
python -m zerotrust.ca.ca init

# Issue certs for two demo users (writes users/<name>/{private.pem, public.pem, cert.json})
python -m zerotrust.ca.ca issue alice
python -m zerotrust.ca.ca issue bob

# Confirm a cert verifies against the CA trust anchor
python -m zerotrust.ca.ca verify users/alice/cert.json
```

### 4. Server / client (Phase 2)

The `zerotrust.server.main` and `zerotrust.client.cli` entry points raise
`NotImplementedError` until Phase 2 issues #5 and #9 land. The legacy
prototype (`legacy/server_x509.py`, `legacy/client_x509.py`) demonstrates a
working RSA-OAEP + HKDF handshake against X.509 certs and is a useful
reference, but it does **not** match the frozen architecture.

## Demo password handling

Per `AI.md` §3.10, all PEM-encoded private keys are protected with
`BestAvailableEncryption(password)`. For demo and testing, the CA CLI
accepts:

1. `--password <pw>` argument (highest priority)
2. `ZEROTRUST_CA_PASSWORD` environment variable
3. The hard-coded fallback `demo-password` (for grading convenience only)

This fallback is documented here, as required. Production deployments would
prompt interactively or use an OS keychain.

## Section 2 — Secure Handshake and Session Key Establishment

The assignment forbids using `ssl`, `pyOpenSSL`, or any pre-built secure-channel
library, so we hand-rolled the parts TLS would otherwise have done. Both sides
walk a five-step ladder (see `ARCHITECTURE.md` §7.4 for the full diagram):

```
HELLO ↔  →  KEY_EXCHANGE  →  AUTH_RESPONSE  →  SESSION_OK
```

`HELLO` exchanges each peer's CA-signed certificate and a fresh 16-byte nonce;
both sides verify the peer cert against the same trust anchor before reading
the embedded public key. The client then RSA-OAEP-encrypts a 32-byte
pre-master under the server's pubkey and sends `KEY_EXCHANGE`. From the two
nonces and the pre-master, both sides bind a transcript hash
`SHA-256(nonce_c ‖ nonce_s ‖ pre_master_ciphertext)`; the AUTH_RESPONSE and
SESSION_OK signatures cover that hash, so a man-in-the-middle who replays
fragments of an earlier handshake cannot reconstruct a valid signature.
**Both** sides sign the transcript (mutual PoP), so an attacker who steals one
private key can still not impersonate the other party. Finally HKDF-SHA256 is
seeded with `salt = nonce_c ‖ nonce_s`, `ikm = pre_master`, and the frozen
info string `b"zerotrust-v1"` to derive directional `c2s_key` and `s2c_key`.

We rejected a pure shared-symmetric-key design (no forward secrecy: a leaked
long-term key decrypts every past session) and a Diffie-Hellman ladder (an
extra primitive on top of the RSA stack already mandated for signatures and
cert verification). RSA-OAEP transport keeps the cryptographic surface to a
single algorithm family and matches the constraints in `ARCHITECTURE.md` §2.

Demo (after CA bootstrap from Section 1):

```bash
python -m zerotrust.server.main &
python -m zerotrust.client.cli --user alice login
# → Authenticated as alice; session established with zerotrust-server.
```

## Section 3 — Secure File Encryption and Upload

Every file is encrypted with a **fresh** AES-256-GCM key. We chose GCM over
CBC+HMAC because it is single-pass authenticated encryption — one primitive,
one nonce, one auth tag — which leaves fewer composition mistakes for a
reviewer to find. The key is 32 random bytes from `os.urandom`; the 12-byte
GCM nonce comes from the same source on every call, so the `(key, nonce)`
pair is unique by construction without any deterministic-nonce optimisation.

The AAD bound into the tag is `f"{file_id}|{sender}|{recipient}".encode()`
(see `ARCHITECTURE.md` §7.7). This stops the most natural attack on a
zero-trust drop server: without AAD, a curious server could paste Alice→Bob's
ciphertext into Carol→Dave's metadata row and the GCM decryption would still
succeed. With it, the auth tag depends on the routing context, so swapping
breaks the tag and the recipient sees a `CryptoError`.

The per-file AES key never leaves the client. We wrap it with RSA-OAEP-SHA256
under the **recipient's** CA-signed public key, fetched at upload time via
`GET_PUBKEY` and re-verified locally against the CA trust anchor. The server
stores only the ciphertext on disk and a metadata row with the wrapped key,
nonce, AAD, hashes and origin signature — schema in `ARCHITECTURE.md` §5.
Ciphertext lives in `server/storage/files/<file_id>.bin`; writes are done
through a `*.bin.tmp` + `os.replace` so a crash mid-upload leaves no
half-files.

Demo:

```bash
python -m zerotrust.client.cli --user alice upload bob ./report.pdf
# → Uploaded file_id=<uuid> to bob; expires=<unix>
```

## Section 4 — Digital Signature and Integrity Verification

Every upload carries an RSA-PSS signature over the canonical JSON of the
seven-field origin struct from `ARCHITECTURE.md` §7.6: `sender`,
`recipient`, `file_id`, `ciphertext_sha256`, `wrapped_key_sha256`,
`timestamp`, `expiration`. The signer hashes the bytes produced by
`canonical_json` (`sort_keys=True, separators=(",", ":")`); any whitespace
drift invalidates the signature, so canonical serialisation is the single
source of truth.

The key trick is binding **both** `ciphertext_sha256` AND `wrapped_key_sha256`
in the same struct. Binding only the ciphertext would let a malicious server
splice in a wrapped key under an attacker's pubkey; binding only the wrapped
key would let it substitute a different ciphertext. Binding both forces the
server to relay exactly what the sender signed — or surface as `AUTH_FAILED`.

We chose RSA-PSS over PKCS#1 v1.5 because PSS has the cleaner provable
security argument and the implementation cost is identical. Staying RSA-only
across signatures, OAEP, and the handshake keeps the asymmetric stack to a
single algorithm family.

Verification runs twice. The server re-runs `verify_origin_struct` on every
`UPLOAD_REQUEST`, so tampered or replayed packages never reach the DB. On
`DOWNLOAD_RESPONSE` the recipient re-verifies (#18 / M3) — server-side
success is not authority.

Demo:

```bash
pytest zerotrust/tests/test_server_upload.py -k tampered
# → tampered ciphertext → AUTH_FAILED, no disk write, no row
```

## Frozen Cryptographic Choices

| Purpose | Algorithm |
|---|---|
| Asymmetric (signatures, key wrap, session establishment) | RSA-2048 |
| Signature padding | RSA-PSS (SHA-256, MGF1, salt = digest length) |
| Key wrapping & session key transport | RSA-OAEP (SHA-256, MGF1) |
| Symmetric encryption | AES-256-GCM |
| Key derivation | HKDF-SHA256 |
| Hash | SHA-256 |
| Random source | `os.urandom()` / `secrets` only |

Any change requires updating `ARCHITECTURE.md` §2 and notifying the team.

## Section 5 — Secure Retrieval and Access Control

To retrieve a file, the recipient first sends a `LIST_PENDING` envelope to discover the available file IDs, sizes, and expiration times. The server returns a list of files where the recipient matches the authenticated peer subject and the status is still `pending`. The recipient then issues a `DOWNLOAD_REQUEST` for a specific file ID.

The server enforces access control at a strict "chokepoint" before touching the filesystem. Crucially, the server relies exclusively on the handshake-proven `peer_subject` for authorization, deliberately ignoring any user-supplied recipient hints in the payload. The chokepoint ensures the file is still `pending`; if the row has transitioned, it fails closed, mapping the internal status directly to wire errors (`NOT_AUTHORIZED` for mismatched recipients, `EXPIRED` for timed-out files, and `REVOKED` for files recalled by the sender).

Upon receiving the `DOWNLOAD_RESPONSE`, the recipient executes a strict verify-then-decrypt sequence. First, the sender's embedded certificate is verified against the CA trust anchor. Second, the RSA-PSS origin signature is verified over the canonical metadata struct to ensure the ciphertext and wrapped key hashes match the sender's original intent. Third, the AES key is unwrapped using the recipient's private key. Finally, the ciphertext is decrypted via AES-GCM. The GCM authentication tag includes the AAD binding (`file_id|sender|recipient`), which mathematically guarantees that the server has not maliciously substituted another ciphertext.

```bash
# Terminal 1: Server
python -m zerotrust.server.main &

# Terminal 2: Alice uploads
python -m zerotrust.client.cli --user alice upload bob ./report.pdf

# Terminal 3: Bob downloads
python -m zerotrust.client.cli --user bob list
python -m zerotrust.client.cli --user bob download <file_id>
# → Produces report.pdf in client_bob/downloads/
```

## Section 6 — File Expiration

The system relies on two distinct, real-time clocks: a 30-second freshness window for envelope nonces to prevent replay attacks, and a per-file `expiration` field governing retention time (defaulting to 7 days). These concepts are strictly separated in implementation.

A background cleanup thread runs every 60 seconds to enforce these constraints on the server. It purges `seen_nonces` older than 5 minutes to prevent the SQLite cache from growing infinitely, and it sweeps the `files` table, marking any row where `expiration < now()` as `expired`. It then deletes the underlying ciphertext blob to reclaim disk space.

Relying on the `expiration` integer alone is insufficient for a fail-closed architecture. Without the cleanup thread explicitly calling `mark_status('expired')`, a stale row would sit in the database with a `pending` status, requiring downstream handlers to implement redundant time checks. By aggressively transitioning the state machine to a terminal status, the server ensures that any late `DOWNLOAD_REQUEST` immediately trips the access control chokepoint and is rejected.

## Section 7 — Security Analysis

**Threat model:** The server acts as an untrusted relay. It CAN see metadata (sender identity, recipient identity, file size, timestamps, and upload/download timing patterns). It CANNOT see the plaintext file contents or the AES-256-GCM session key.

**Defended:** The protocol defends against identity substitution through mutual Proof-of-Possession (both sides sign the handshake transcript). Network replay attacks are mitigated by the envelope nonce cache and strict timestamp windows. Ciphertext substitution is defeated by the AES-GCM AAD binding (`file_id|sender|recipient`). Forward integrity is guaranteed by the RSA-PSS origin signature, which cryptographically binds the ciphertext hash and the wrapped key hash to the original sender.

**NOT defended (known limitations per ARCHITECTURE.md §12):** There is no forward secrecy; a compromise of a user's long-term RSA private key allows an attacker to re-decrypt past sessions if they recorded the traffic. There is no traffic-analysis resistance. CA bootstrap is manual, and PEM files are protected only by passwords (including a documented demo password in the config) rather than hardware backing.

For a production deployment, the handshake must adopt ECDHE for forward secrecy, private keys should move to the OS keychain (or TPM/Secure Enclave), and the PKI must support real CRLs or short-lived certificates.

## Division of Labor

### Alp Büyükköse
- **Issues owned:** #6, #7, #8, #15, #16, #17, #18, #19, #22, #23, #27, #29, #32, M1 Foundation.
- **Notable contributions:** Designed M1 foundation architecture, protocol framing, CI pipelines, implemented AES-GCM AAD binding, RSA-PSS signatures, background cleanup threads, replay enforcement, and structured audit logging.
- **Number of commits / PRs:** 24 commits.

### Kerem Hakkı Koç
- **Issues owned:** #5, #14, #16, #17.
- **Notable contributions:** Established the project skeleton, CA structure, SQLite DB schema, multi-threaded server (`ThreadingTCPServer`), CRUD operations, and secure download access controls (chokepoints).
- **Number of commits / PRs:** 5 commits.

### Turgut Köroğlu
- **Issues owned:** None tracked in git log.
- **Notable contributions:** Code review, testing, documentation, and conceptual threat modeling.
- **Number of commits / PRs:** 0 commits.
