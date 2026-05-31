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
| **M2 — Handshake + Upload (parallel)** | ✅ Complete |
| **M3 — Download + Hardening + Bonus** | ✅ Complete |

All three milestones land on `main`. The full 11-step PDF demo is
reproducible from a fresh clone via `bash demo/run_demo.sh` (see
[Section 5 — Secure Retrieval](#section-5--secure-retrieval-and-access-control)).

### Feature inventory

**Required (assignment rubric):**

- Offline **PKI**: custom JSON certificates signed by an in-house CA, no
  X.509 anywhere on the hot path (`zerotrust/ca/`).
- **Mutual handshake** with transcript-bound Proof-of-Possession (both
  sides sign `SHA-256(nonce_c ‖ nonce_s ‖ pre_master_ct)`).
- **End-to-end file encryption**: AES-256-GCM with AAD bound to
  `file_id|sender|recipient`, per-file random key wrapped under the
  recipient's RSA-OAEP-SHA256 pubkey.
- **RSA-PSS origin signatures** over a canonical seven-field metadata
  struct (`ciphertext_sha256`, `wrapped_key_sha256`, `sender`,
  `recipient`, `file_id`, `timestamp`, `expiration`).
- **Access-control chokepoint** that gates every download on the
  handshake-proven `peer_subject`, fail-closed.
- **Expiration enforcement**: per-file TTL plus a background cleanup
  thread that flips expired rows to a terminal status and reclaims
  ciphertext blobs.
- **Replay protection**: 30 s timestamp window plus a server-side
  nonce-cache (`seen_nonces`).
- **Structured audit logging** with sensitive-data sanitisation.

**Bonus features implemented (see [Bonus Features](#bonus-features)):**

- Revocation before download (sender can recall a still-pending file).
- One-time download (server flips `pending → downloaded`, second attempt
  yields `ALREADY_DOWNLOADED`).
- Signed recipient acknowledgement (`DOWNLOAD_ACK`).
- Confidential metadata (filename never enters the protocol).

**Quality bar:** 274 pytest tests (happy + negative path coverage for
handshake, upload, download, revocation, expiration, replay, audit
logging, cleanup), plus a four-stage CI sweep (`ruff`, `bandit`,
`scripts/check_forbidden_imports.py`, `scripts/check_frozen_signatures.py`).

## Module Layout

```
zerotrust/
├── common/                       # shared primitives, never imports server/ or client/
│   ├── crypto_primitives.py      # RSA keygen, RSA-PSS sign/verify, RSA-OAEP, AES-GCM, HKDF
│   ├── protocol.py               # length-prefixed JSON framing, envelopes, MAX 64 MiB
│   ├── canonical.py              # canonical JSON for everything that gets signed
│   ├── file_crypto.py            # encrypt_file_blob (AES-GCM + AAD), decrypt_file_blob
│   ├── key_wrap.py               # wrap_aes_key_for / unwrap_aes_key
│   ├── origin.py                 # sign_origin_struct / verify_origin_struct (RSA-PSS)
│   ├── transcript.py             # SHA-256(nonce_c ‖ nonce_s ‖ pre_master_ct) hash
│   ├── revoke.py                 # canonical struct shared by client+server revoke
│   ├── logger.py                 # structured logger + fingerprint redaction
│   └── exceptions.py             # CryptoError / AuthError / ProtocolError
├── ca/                           # offline CA — custom JSON certs, no X.509
│   ├── cert.py                   # issue_certificate / verify_certificate
│   └── ca.py                     # CLI: init / issue / verify
├── server/                       # untrusted relay — sees ciphertext + routing only
│   ├── main.py                   # ThreadingTCPServer entry point + SIGINT shutdown
│   ├── handler.py                # request dispatcher + access-control chokepoint
│   ├── handshake.py              # server side of mutual PoP handshake
│   ├── store.py                  # SQLite CRUD: files, seen_nonces, acks tables
│   ├── storage_layout.py         # path resolvers for pubkey dir + blob dir
│   ├── replay.py                 # nonce check_and_record + purge_older_than
│   └── cleanup.py                # background thread: expire files + GC nonces
├── client/                       # trusted local CLI
│   ├── cli.py                    # argparse: login / upload / list / download / revoke
│   ├── session.py                # connected_session() context manager
│   ├── handshake.py              # client side of mutual PoP handshake
│   ├── peer.py                   # fetch_peer_cert + CA verification
│   ├── upload.py                 # build origin struct, RSA-PSS sign, send UPLOAD_REQUEST
│   ├── download.py               # list_pending, download_file, verify-then-decrypt
│   └── revoke.py                 # send signed REVOKE_REQUEST, expect REVOKE_ACK
└── tests/                        # 274 tests — see `make test` for the full sweep
    ├── test_ca.py, test_canonical.py, test_crypto.py, test_protocol.py
    ├── test_handshake.py, test_pop.py, test_origin.py, test_key_wrap.py
    ├── test_upload.py, test_server_upload.py, test_file_crypto.py
    ├── test_download.py, test_download_access.py, test_pending_list.py
    ├── test_revocation.py, test_download_ack.py
    ├── test_replay.py, test_replay_enforcement.py, test_cleanup.py
    ├── test_audit_log.py, test_pubkey_directory.py, test_store.py
    ├── test_server_boot.py, test_client_cli.py
    ├── test_integration.py        # full PDF demo as a single pytest
    └── test_demo_script.py        # static asserts on demo/run_demo.sh
```

Other top-level directories:

```
demo/                             # reproducible 11-step PDF demo + tests
├── run_demo.sh                   # one-shot orchestrator (bootstrap → upload → diff)
├── sample_files/                 # fixture inputs for the demo
├── expected_output.txt           # reference run output
└── README.md
webui/                            # OPTIONAL Flask demo UI (separate branch)
scripts/                          # CI helpers: forbidden-imports + frozen-signatures lint
legacy/                           # pre-architecture X.509 prototype — reference only
```

## How to Run

### 1. Setup

```bash
python -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
make install                     # or: pip install -r requirements.txt
```

For development (lint + coverage tools):

```bash
make install-dev
```

### 2. Run the test suite

```bash
make test                        # or: pytest
```

All 274 tests should pass in well under a minute.

### 3. End-to-end demo (one command)

```bash
bash demo/run_demo.sh
```

The orchestrator wipes any previous state, bootstraps the CA, mints
`server` / `alice` / `bob` identities, starts the server in the
background under a `trap`, runs Alice's upload and Bob's download, and
asserts byte-equality between the original and recovered plaintext.
A successful run ends with `Plaintext match — demo OK`.

### 4. Manual two-terminal flow

If you want to drive each step interactively:

```bash
# One-shot bootstrap (CA + server cert + alice + bob)
make demo-setup

# Terminal 1 — protocol server
make server                      # binds 127.0.0.1:5050

# Terminal 2 — client actions
python -m zerotrust.client.cli --user alice login
python -m zerotrust.client.cli --user alice upload bob ./somefile.pdf
python -m zerotrust.client.cli --user bob list
python -m zerotrust.client.cli --user bob download <file_id>
python -m zerotrust.client.cli --user alice revoke <file_id>
```

To add more identities live:

```bash
make user USER=charlie           # ca-issue + client-setup + server-register
```

To peek at server-side state without touching the client:

```bash
make inspect                     # registered pubkeys + DB rows + ciphertext blobs
```

## Demo password handling

Per `AI.md` §3.10, all PEM-encoded private keys are protected with
`BestAvailableEncryption(password)`. The CA and the client CLI both
resolve their passwords through the same three-step ladder:

1. Explicit `--password <pw>` argument (highest priority).
2. Environment variable:
   - `ZEROTRUST_CA_PASSWORD` for the offline CA tooling.
   - `ZEROTRUST_USER_PASSWORD` for the client CLI's per-user private key.
3. The hard-coded fallback `demo-password` (for grading convenience).

This fallback is documented here, as required by the assignment. The
demo orchestrator (`demo/run_demo.sh`) and the optional `webui/` UI
both rely on the env-var path so prompts never block. Production
deployments would prompt interactively or pull the password from an OS
keychain (see [Section 7 — Security Analysis](#section-7--security-analysis)).

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

### Reproducible end-to-end demo

The full 11-step PDF scenario is packaged at [`demo/run_demo.sh`](demo/run_demo.sh). From a fresh clone, two commands replay the whole flow without any manual terminal juggling:

```bash
make install
bash demo/run_demo.sh
```

The orchestrator bootstraps the CA, issues `server`/`alice`/`bob` identities, registers recipient pubkeys, starts the server in the background under a `trap` (so it is killed even if the script aborts), runs Alice's upload and Bob's list+download, and asserts the recovered plaintext byte-matches the original. See [`demo/README.md`](demo/README.md) for the sample-file conventions and where the recovered plaintext lands.

A captured run is embedded below (the `<FILE_ID>`/`<UNIX_TS>` placeholders correspond to per-run UUIDs and Unix timestamps that vary; the structure and final banner are stable):

```
=== 4. Start server in background on port 5050 ===
Server running (pid=<PID>).
=== 5. Alice uploads demo/sample_files/report.pdf to bob ===
Uploaded file_id=<FILE_ID> to bob; expires=<UNIX_TS>
=== 6. Bob lists his pending files ===
<FILE_ID> sender=alice size=<N> expires=<UNIX_TS>
=== 7. Bob downloads file_id=<FILE_ID> ===
Downloaded file_id=<FILE_ID>
=== 8. Verify plaintext match ===
Plaintext match — demo OK
```

A still screenshot of the same run lives at [`demo/screenshot.png`](demo/screenshot.png) — capture it on a developer machine after the demo prints `Plaintext match — demo OK`.

## Section 6 — File Expiration

The system relies on two distinct, real-time clocks: a 30-second freshness window for envelope nonces to prevent replay attacks, and a per-file `expiration` field governing retention time (defaulting to 7 days). These concepts are strictly separated in implementation.

A background cleanup thread runs every 60 seconds to enforce these constraints on the server. It purges `seen_nonces` older than 5 minutes to prevent the SQLite cache from growing infinitely, and it sweeps the `files` table, marking any row where `expiration < now()` as `expired`. It then deletes the underlying ciphertext blob to reclaim disk space.

Relying on the `expiration` integer alone is insufficient for a fail-closed architecture. Without the cleanup thread explicitly calling `mark_status('expired')`, a stale row would sit in the database with a `pending` status, requiring downstream handlers to implement redundant time checks. By aggressively transitioning the state machine to a terminal status, the server ensures that any late `DOWNLOAD_REQUEST` immediately trips the access control chokepoint and is rejected.

## Bonus Features

The assignment lists seven optional bonus tracks; the project implements
four of them, each enforced server-side (not just at the CLI) and
covered by dedicated tests.

### 1. Revocation before download

A sender can recall a still-pending file by sending a signed
`REVOKE_REQUEST` carrying the canonical revoke struct from
`zerotrust/common/revoke.py`. The server verifies the RSA-PSS
signature against the sender's CA-signed pubkey, asserts the row's
sender matches the handshake-proven `peer_subject`, and atomically
flips the status to `revoked`. A second revoke of the same file is a
no-op success (`REVOKE_ACK`), so retry-safe CLIs can re-issue the
request without a state machine of their own. Any later
`DOWNLOAD_REQUEST` for a revoked file is rejected with `REVOKED` at
the chokepoint before the blob is even read from disk. Both successful
revokes and rejected downloads of revoked files land in the audit log
under `event=revoke_*` / `event=download_deny reason=revoked`.

### 2. One-time download

A successful `DOWNLOAD_RESPONSE` flips the row's status from `pending`
to `downloaded` inside the same transaction that returns the
ciphertext, so the "successful retrieval" boundary is bound to the
server having sent the response. Any subsequent `DOWNLOAD_REQUEST` for
the same `file_id` trips the chokepoint and yields
`ALREADY_DOWNLOADED`. Failed mid-flight transmissions do *not* consume
the file: the status update happens only after the response payload is
fully written to the socket, so a crashed download leaves the row
`pending` for retry. Each repeated attempt is logged with
`event=download_deny reason=status_downloaded` so abuse patterns are
visible in the audit trail.

### 3. Signed recipient acknowledgement

After Bob verifies and decrypts a download, his client sends a
`DOWNLOAD_ACK` envelope carrying an RSA-PSS signature over a
canonical struct of `(file_id, recipient, ack_timestamp)`. The server
verifies the signature against Bob's CA-signed pubkey and persists
the row in a dedicated `acks` table (`zerotrust/server/store.py`).
Because the ACK is generated *only* after a successful local
verify-then-decrypt (`zerotrust/client/download.py`), an ACK in the
database is cryptographic proof that the recipient received and
authenticated the exact ciphertext Alice signed in the origin struct.
The server tolerates `STALE` / `REPLAY` rejections on the ACK
specifically so a successful decrypt is never re-tried in a way that
loses the plaintext.

### 4. Confidential metadata

The protocol envelope intentionally never carries the filename. The
server's view of a file (`make inspect`) is
`(file_id, sender_id, recipient_id, status, upload_timestamp,
expiration, ciphertext_size)` plus the AES-GCM ciphertext blob — that
is the entire metadata surface. Routing/access-control fields
(`sender`, `recipient`, `file_id`) must stay visible so the chokepoint
can enforce delivery; everything else, including the original
filename and any user-supplied description, lives only on the
endpoints. The optional `webui/` UI demonstrates the trade-off
explicitly: it remembers the original filename in Flask process
memory so the browser saves `report.pdf` instead of the bare UUID,
but the protocol layer between client and server never sees that
string. Re-deploying the UI on a remote host would move the filename
out of the "local trusted client" zone, which is why we keep
`webui/` opt-in and local-only.

## Section 7 — Security Analysis

**Threat model:** The server acts as an untrusted relay. It CAN see
metadata (sender identity, recipient identity, file size, timestamps,
and upload/download timing patterns). It CANNOT see the plaintext file
contents, the AES-256-GCM session key, or filenames.

### Attack scenarios and defences

- **MITM during handshake** — both sides exchange CA-signed certs in
  `HELLO`, verify against the same trust anchor, and sign the transcript
  hash `SHA-256(nonce_c ‖ nonce_s ‖ pre_master_ct)`. An attacker who
  steals one private key still cannot impersonate the other party.
- **Replayed upload / download requests** — every envelope carries a
  fresh 16-byte nonce + Unix timestamp; the server's `seen_nonces` cache
  rejects duplicates and the 30 s window drops stale envelopes.
- **Unauthorised file access** — the chokepoint in `handler.py` gates
  every `DOWNLOAD_REQUEST` on the handshake-proven `peer_subject`,
  fail-closed. Generic `AUTH_FAILED` is returned to avoid an oracle.
- **Forged metadata** — `UPLOAD_REQUEST` carries an RSA-PSS origin
  signature over a canonical struct that binds `ciphertext_sha256`,
  `wrapped_key_sha256`, sender, recipient, file_id, timestamp,
  expiration. Server and recipient both re-verify.
- **Malicious server-side ciphertext / wrapped-key swap** — defeated by
  the AES-GCM AAD binding (`file_id|sender|recipient`) and by the
  origin signature covering both ciphertext and wrapped-key hashes.
- **Compromised client private key** — *not defended*. Anyone with
  Bob's PEM and password can decrypt his future and (recorded) past
  traffic. Mitigation belongs in production (HSM / OS keychain).
- **Weak randomness** — all nonces, AES keys, and pre-master values
  come from `os.urandom` / `secrets`; no deterministic-nonce paths.
- **Log leakage** — `zerotrust/common/logger.py` redacts cert
  fingerprints and refuses to log private-key material or ciphertext.
- **Metadata leakage (filenames, sizes, timing)** — filenames never
  enter the protocol envelope (confidential metadata bonus). File
  sizes and upload/download timing remain visible to the server by
  design; a real deployment would pad to size buckets and add cover
  traffic.

**Out of scope (known limitations per ARCHITECTURE.md §12):** no
forward secrecy (long-term RSA keys decrypt past sessions if traffic
was recorded), no traffic-analysis resistance, manual CA bootstrap,
PEM files protected only by passwords (including the documented demo
password). Production deployment would adopt ECDHE for forward
secrecy, move private keys to the OS keychain (or TPM / Secure
Enclave), and support real CRLs or short-lived certificates.

## Division of Labor

### Team workflow

Every unit of work in the project corresponds to a GitHub issue. Work
flowed through a strict branch-per-issue → pull-request → review →
merge pipeline:

1. **Issues** (`#1` … `#32`) defined scope, acceptance criteria, and
   the milestone (M1 foundation, M2 handshake + upload, M3 download +
   hardening + bonus).
2. **Branches** named `feat/issue-NN-*` were opened off `main`; the
   owner implemented the issue in isolation.
3. **CI on every push** ran the four-stage sweep before any merge was
   possible: `ruff` (style), `bandit` (security lint), the custom
   `scripts/check_forbidden_imports.py` (no `ssl` / `pyOpenSSL`, no
   plaintext storage paths), and `scripts/check_frozen_signatures.py`
   (every public function signature still matches `ARCHITECTURE.md`'s
   inventory).
4. **Pull requests** required passing CI and a code review by at least
   one other team member. **Alp owned the merge button** and resolved
   any merge conflicts that arose when parallel M2/M3 branches landed
   close together.
5. **Frozen contracts** — `ARCHITECTURE.md` (system design, wire
   protocol §7, SQLite schema §5, frozen signatures §10.1) and `AI.md`
   (zero-trust coding rules) were authored in M1 and treated as
   read-only specs afterwards; the frozen-signatures linter mechanically
   enforces that runtime code stays faithful to the design.

This separation let three people work in parallel after M1 without
stepping on each other, while keeping the cryptographic core
auditable: every PR diff lived under a known issue, every issue had
acceptance criteria, every merge passed CI.

### Issue ownership

| Member | Owned issues | Areas of responsibility |
|---|---|---|
| **Alp Büyükköse** | M1 foundation (#1–#4), #6, #7, #8, #19, #20, #22b, #24, #25, #26, #27 | Cryptographic core, operational hardening, CI pipeline, frozen contracts, merge ownership |
| **Kerem Hakkı Koç** | #5, #13, #14, #15, #16, #17, #21, #22a | Server architecture, SQLite storage, access-control chokepoint, secure download |
| **Turgut Köroğlu** | #9, #10, #11a, #11b, #12, #18, #23, #28 | Client-side flows, integration tests, documentation, demo orchestration |

### Areas in detail

**Alp Büyükköse — Cryptographic core, operational hardening, pipeline**
authored the frozen design contract (`ARCHITECTURE.md`, `AI.md`) and
the frozen-signature inventory the CI linter enforces against drift.
Implemented the cryptographic primitives — AES-256-GCM with AAD binding
(`file_id|sender|recipient`), RSA-PSS origin signatures over the
canonical metadata struct, RSA-OAEP key wrapping — and the operational
defences (replay nonce cache, background cleanup thread, structured
audit logging). Maintained the four-stage CI gate (ruff, bandit,
forbidden-imports, frozen-signatures) and acted as merge owner /
conflict resolver across milestone PRs.

**Kerem Hakkı Koç — Server architecture and access control** bootstrapped
the project skeleton and the offline CA tooling (`zerotrust/ca/`),
designed the SQLite metadata schema (`zerotrust/server/store.py`,
`storage_layout.py`), implemented the multi-threaded TCP server
(`ThreadingTCPServer`) with daemon workers and graceful SIGINT shutdown,
and built the request dispatcher (`handler.py`). Owns the access-control
chokepoint that gates every `DOWNLOAD_REQUEST` against the
handshake-proven `peer_subject` and the pubkey-directory lookup path.

**Turgut Köroğlu — Client flows, integration tests, documentation**
implemented the client-side handshake + session lifecycle, the upload
and download CLI verbs, and the integration tests under
`zerotrust/tests/test_integration.py`. Drove the README documentation
pass for sections covering the handshake, upload, retrieval, and
demo, and authored the demo orchestrator (`demo/run_demo.sh`) plus the
static demo-script audit (`tests/test_demo_script.py`).
