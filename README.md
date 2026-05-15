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

Because the assignment requirements strictly prohibit... (Antigravity'nin metninin devamı)

## Section 3 — Secure File Encryption and Upload

For end-to-end encryption, we selected AES-256-GCM... (Antigravity'nin metninin devamı)

## Section 4 — Digital Signature and Integrity Verification

To guarantee non-repudiation and origin authenticity... (Antigravity'nin metninin devamı)

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

## Security Analysis

To be written in Phase 3 (issue #22b). The known limitations enumerated in
`ARCHITECTURE.md` §12 will be discussed there.
