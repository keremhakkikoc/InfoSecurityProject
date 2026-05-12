#!/usr/bin/env bash
# Bulk-create the 26 GitHub issues for M2 and M3 (23 mandatory + 3 bonus).
#
# Prerequisites:
#   brew install gh   # (or your platform's installer)
#   gh auth login     # interactive — pick your GitHub account
#
# Usage:
#   bash scripts/create_github_issues.sh
#
# Idempotency: gh issue create always opens a new issue, so DO NOT run this
# twice without checking — you'll end up with duplicates. If you need to
# restart partway, delete the duplicates from the GitHub UI first.

set -euo pipefail

REPO="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "Target repo: $REPO"
echo

# ---------------------------------------------------------------------------
# Labels — create them once (idempotent via `|| true`).
# Color codes are hex without `#`.
# ---------------------------------------------------------------------------

create_label() {
    local name="$1" color="$2" desc="$3"
    gh label create "$name" --color "$color" --description "$desc" --force >/dev/null 2>&1 || true
}

echo "Creating labels..."
create_label "milestone-2" "1d76db" "M2 — Handshake + Upload (parallel)"
create_label "milestone-3" "5319e7" "M3 — Download + Hardening + Bonus"
create_label "area: common" "fbca04" "zerotrust/common/*"
create_label "area: ca"     "fbca04" "zerotrust/ca/*"
create_label "area: server" "fbca04" "zerotrust/server/*"
create_label "area: client" "fbca04" "zerotrust/client/*"
create_label "bonus"        "ffd700" "Optional bonus feature (extra points)"
create_label "docs"         "0e8a16" "Documentation"
create_label "tests"        "0e8a16" "Test code"
create_label "points: 1"    "c5def5" "Story points: 1"
create_label "points: 2"    "c5def5" "Story points: 2"
create_label "points: 3"    "c5def5" "Story points: 3"
create_label "points: 5"    "c5def5" "Story points: 5"

# ---------------------------------------------------------------------------
# Milestones — created via REST API since `gh milestone` is not built in.
# ---------------------------------------------------------------------------

create_milestone() {
    local title="$1" description="$2"
    # 1 returns the existing milestone id if title matches; otherwise creates.
    gh api -X POST "repos/$REPO/milestones" \
        -f title="$title" \
        -f description="$description" \
        -f state="open" >/dev/null 2>&1 || true
}

echo "Creating milestones..."
create_milestone "M2 — Handshake + Upload" \
    "Mutual auth, secure session, encrypted upload. Done = Alice can upload an encrypted file for Bob; server stores ciphertext + metadata without seeing plaintext."
create_milestone "M3 — Download + Hardening + Bonus" \
    "Recipient retrieval, hardening, bonuses, integration demo. Done = PDF's 11-step demo runs end-to-end."

# ---------------------------------------------------------------------------
# Helper: create one issue.
# Args: title, milestone_title, label_csv, body
# ---------------------------------------------------------------------------

create_issue() {
    local title="$1" milestone="$2" labels="$3" body="$4"
    echo "  + $title"
    gh issue create \
        --repo "$REPO" \
        --title "$title" \
        --milestone "$milestone" \
        --label "$labels" \
        --body "$body" >/dev/null
}

# ---------------------------------------------------------------------------
# Milestone 2 — Handshake + Upload (13 issues, 33 points)
# ---------------------------------------------------------------------------

echo
echo "Creating M2 issues..."

create_issue "#5 Multithreading server — ThreadingTCPServer or thread-per-client" \
"M2 — Handshake + Upload" \
"milestone-2,area: server,points: 2" \
"## Goal
Accept multiple concurrent client connections.

## Implementation
- Use \`socketserver.ThreadingTCPServer\` OR raw \`threading.Thread\` per accept (see ARCHITECTURE.md §6).
- Each thread MUST open its own \`sqlite3.Connection\` (ARCHITECTURE.md §5/§6).
- Server entry point: \`zerotrust/server/main.py\` (currently NotImplementedError stub).

## Acceptance Criteria
- [ ] \`python -m zerotrust.server.main\` listens on a configurable port.
- [ ] Two clients can connect in parallel without blocking each other.
- [ ] Graceful shutdown on SIGINT.
- [ ] Connection-level errors are logged but don't take down the server.

## Files
- \`zerotrust/server/main.py\`
- \`zerotrust/server/handler.py\` (skeleton already exists)

## References
ARCHITECTURE.md §6 (Concurrency Model), §10 (Module Layout)"

create_issue "#6 Certificate verification — CA signature + expiration + subject" \
"M2 — Handshake + Upload" \
"milestone-2,area: common,points: 2" \
"## Goal
Make \`verify_certificate\` enforce all three checks from ARCHITECTURE.md §3.4.

## Implementation
Currently \`zerotrust/ca/cert.py:verify_certificate(cert, ca_pubkey_pem)\` checks:
1. CA signature ✅
2. Expiration window ✅
3. Subject match ❌ — add optional \`expected_subject\` parameter

## Acceptance Criteria
- [ ] New signature: \`verify_certificate(cert, ca_pubkey_pem, expected_subject=None) -> bool\` (backwards compatible).
- [ ] When \`expected_subject\` is given, \`cert['subject']\` must match exactly.
- [ ] Update EXPECTED in \`scripts/check_frozen_signatures.py\` AND ARCHITECTURE.md §10.1 in the same PR.
- [ ] Add at least 2 tests: subject match success + subject mismatch failure.

## References
ARCHITECTURE.md §3.4, §10.1"

create_issue "#7 Proof-of-possession — nonce sign + verify" \
"M2 — Handshake + Upload" \
"milestone-2,area: common,points: 3" \
"## Goal
Both parties must sign a nonce-bound transcript to prove they hold the private key matching the cert they presented.

## Implementation
- Use \`rsa_sign\` / \`rsa_verify\` from \`zerotrust/common/crypto_primitives.py\`.
- Transcript hash per ARCHITECTURE.md §7.4: \`SHA-256(nonce_c || nonce_s || pre_master_ciphertext)\`.
- Server signs transcript inside SESSION_OK; client verifies before considering session authenticated.

## Acceptance Criteria
- [ ] Server PoP signature included in SESSION_OK.
- [ ] Client PoP signature in AUTH_RESPONSE.
- [ ] Both verifications fail-closed (return False, no exception leak).
- [ ] Tests: correct sig accepts, tampered sig rejects.

## References
ARCHITECTURE.md §7.4 (mutual PoP), §7.5 (HKDF)"

create_issue "#8 Session key establishment — RSA-OAEP transport + HKDF" \
"M2 — Handshake + Upload" \
"milestone-2,area: common,points: 5" \
"## Goal
Implement the full handshake state machine (ARCHITECTURE.md §7.4) and derive \`c2s_key\` + \`s2c_key\`.

## Implementation
- Client sends KEY_EXCHANGE with \`rsa_oaep_encrypt(server_pub, pre_master)\`.
- Server decrypts with \`rsa_oaep_decrypt\`.
- Both derive: \`HKDF(pre_master, salt=nonce_c||nonce_s, info=b'zerotrust-v1', length=64)\`.
- Split: c2s = okm[0:32], s2c = okm[32:64].

## Acceptance Criteria
- [ ] \`server/handshake.py:perform_server_handshake\` and \`client/handshake.py:perform_client_handshake\` return the documented session-state dict.
- [ ] Returned dict shape: \`{peer_subject, peer_cert, c2s_key, s2c_key, transcript_hash}\`.
- [ ] Integration test: two-process handshake + key match.

## Dependencies
Blocked by #6 (cert verification) and #7 (PoP signatures).

## References
ARCHITECTURE.md §7.4, §7.5"

create_issue "#9 CLI login — handshake-triggering client command" \
"M2 — Handshake + Upload" \
"milestone-2,area: client,points: 2" \
"## Goal
Provide \`python -m zerotrust.client.cli --user alice login\` that performs the handshake and prints a success line.

## Implementation
- Read \`client_<user>/config.json\` for server_host / port / username.
- Load \`cert.json\`, \`private.pem\`, ask for password (or env var ZEROTRUST_USER_PASSWORD).
- Call \`perform_client_handshake\`.

## Acceptance Criteria
- [ ] Successful login prints \`Authenticated as <username>; session established.\`
- [ ] Failed login (wrong password, bad cert) exits non-zero with generic \`AUTH_FAILED\` message.

## References
ARCHITECTURE.md §4.2 (client storage layout)"

create_issue "#10 AES-GCM file encryption with AAD binding" \
"M2 — Handshake + Upload" \
"milestone-2,area: common,points: 2" \
"## Goal
Encrypt a file with a fresh AES-256-GCM key, binding ciphertext to its context.

## Implementation
- Fresh 32-byte key from \`os.urandom\`.
- Fresh 12-byte nonce from \`aes_gcm_encrypt\`.
- AAD: \`f'{file_id}|{sender_id}|{recipient_id}'.encode()\` per §7.7.

## Acceptance Criteria
- [ ] Helper \`encrypt_file_blob(plaintext_bytes, file_id, sender, recipient) -> (nonce, ciphertext, aes_key)\`.
- [ ] Decryption with wrong AAD raises CryptoError.
- [ ] Tests cover AAD mismatch + ciphertext bit-flip.

## References
ARCHITECTURE.md §7.7 (AEAD AAD)"

create_issue "#11a Key wrapping — wrap AES key with recipient's pubkey" \
"M2 — Handshake + Upload" \
"milestone-2,area: client,points: 2" \
"## Goal
Wrap the per-file AES key under the intended recipient's RSA pubkey using OAEP.

## Implementation
- \`rsa_oaep_encrypt(recipient_pub_pem, aes_key) -> wrapped_key_bytes\`.
- Recipient pubkey obtained via GET_PUBKEY (#21).

## Acceptance Criteria
- [ ] Wrapped key embedded in UPLOAD_REQUEST payload (base64).
- [ ] Tests: only intended recipient can unwrap.

## References
ARCHITECTURE.md §7.6"

create_issue "#11b Origin signature — RSA-PSS over canonical struct" \
"M2 — Handshake + Upload" \
"milestone-2,area: client,points: 3" \
"## Goal
Sender signs the canonical struct from ARCHITECTURE.md §7.6 so the server (and recipient) can verify origin.

## Implementation
- Build canonical JSON: sender, recipient, file_id, ciphertext_sha256, wrapped_key_sha256, timestamp, expiration.
- \`rsa_sign(sender_priv, password, canonical_bytes)\`.

## Acceptance Criteria
- [ ] Signature attached to UPLOAD_REQUEST.
- [ ] Tests: tampering ANY field of the canonical struct invalidates the signature.

## Dependencies
Pair with #13 (server-side verification).

## References
ARCHITECTURE.md §7.6"

create_issue "#12 Upload CLI + packaging — read file, call crypto, send" \
"M2 — Handshake + Upload" \
"milestone-2,area: client,points: 3" \
"## Goal
\`python -m zerotrust.client.cli --user alice upload bob ./file.pdf [--expires 7d]\`

## Implementation
- After handshake, fetch bob's cert via GET_PUBKEY.
- Call helpers from #10, #11a, #11b.
- Build UPLOAD_REQUEST envelope, send, await UPLOAD_ACK.

## Acceptance Criteria
- [ ] Prints \`Uploaded file_id=<uuid> to <recipient>; expires <unix>\`.
- [ ] On server error, exit non-zero with the error code (no internals leaked).

## References
ARCHITECTURE.md §8 (file lifecycle — upload)"

create_issue "#13 Server-side signature verification + write ciphertext to disk" \
"M2 — Handshake + Upload" \
"milestone-2,area: server,points: 3" \
"## Goal
On UPLOAD_REQUEST, verify sender's cert + PoP + origin signature + freshness, then write blob.

## Implementation
- Verify sender cert against CA trust anchor.
- Recompute canonical struct and call \`rsa_verify\`.
- Replay/freshness via \`server/replay.py:check_and_record\`.
- Write ciphertext to \`server/storage/files/<file_id>.bin\`.

## Acceptance Criteria
- [ ] Any failure -> generic UPLOAD_ACK error (AUTH_FAILED / MALFORMED / etc.), detailed log.
- [ ] Success -> metadata row inserted (issue #14).

## Dependencies
Pair with #11b. Depends on #14 (metadata store).

## References
ARCHITECTURE.md §7.6, §7.8, §8"

create_issue "#14 SQLite metadata — schema + CRUD" \
"M2 — Handshake + Upload" \
"milestone-2,area: server,points: 3" \
"## Goal
Implement \`server/store.py\` per ARCHITECTURE.md §5 schema.

## Implementation
- \`init_schema\` creates \`files\`, \`seen_nonces\`, \`acks\` tables.
- \`insert_file\`, \`list_pending_for\`, \`get_file\`, \`mark_status\`.
- Each thread MUST open its own connection.

## Acceptance Criteria
- [ ] Schema matches ARCHITECTURE.md §5 exactly.
- [ ] Tests cover insert -> retrieve -> mark_status flow.
- [ ] Index on (recipient_id, status) exists.

## References
ARCHITECTURE.md §5"

create_issue "#21 Public key directory — GET_PUBKEY / PUBKEY_RESPONSE" \
"M2 — Handshake + Upload" \
"milestone-2,area: server,points: 2" \
"## Goal
Allow a logged-in client to fetch another user's CA-signed cert from the server.

## Implementation
- Server side: load \`server/storage/pubkeys/<username>.json\`.
- Client side: helper \`fetch_peer_cert(session, username) -> dict\`.

## Acceptance Criteria
- [ ] Unknown user -> NOT_FOUND error code.
- [ ] Returned cert verifies against CA trust anchor at the client.

## References
ARCHITECTURE.md §7.3, §4.1"

create_issue "#22a README — handshake + upload sections" \
"M2 — Handshake + Upload" \
"milestone-2,docs,points: 1" \
"## Goal
Replace the (TODO) sections 2, 3, 4 of README.md with prose explaining the M2 handshake + upload.

## Acceptance Criteria
- [ ] Sections updated: 'Secure Handshake', 'Secure File Encryption and Upload', 'Digital Signature and Integrity Verification'.
- [ ] Each section references the relevant ARCHITECTURE.md anchor.
- [ ] Include the 3-terminal demo commands.

## References
README.md sections 2, 3, 4"

# ---------------------------------------------------------------------------
# Milestone 3 — Download + Hardening + Bonus (13 issues, 30 points)
# ---------------------------------------------------------------------------

echo
echo "Creating M3 issues..."

create_issue "#15 Pending file listing — LIST_PENDING / PENDING_LIST" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,area: client,points: 2" \
"## Goal
Recipient asks server for their pending files; gets array of metadata.

## Implementation
- Server: \`list_pending_for(conn, recipient)\` returns rows where recipient=me AND status='pending' AND expiration > now().
- Client: \`python -m zerotrust.client.cli --user bob list\` shows file_id, sender, size, expiration.

## Acceptance Criteria
- [ ] Empty list when nothing pending.
- [ ] Expired files excluded.
- [ ] Tests cover recipient mismatch (must NOT leak others' files).

## References
ARCHITECTURE.md §7.3, §8"

create_issue "#16 Access + expiration enforcement" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,points: 2" \
"## Goal
Before serving a file, server checks recipient match, status, and expiration.

## Implementation
- Reject NOT_AUTHORIZED if recipient != session user.
- Reject EXPIRED if expiration < now().
- Reject NOT_FOUND if no row.

## Acceptance Criteria
- [ ] All three failure paths surface generic error codes to client (detail in audit log).
- [ ] Tests for each rejection path.

## References
ARCHITECTURE.md §8 (expiration), §7.9"

create_issue "#17 Secure download — DOWNLOAD_REQUEST / DOWNLOAD_RESPONSE" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,area: client,points: 2" \
"## Goal
Recipient downloads the full encrypted package (ciphertext + wrapped key + signature + cert).

## Implementation
- Client: \`python -m zerotrust.client.cli --user bob download <file_id>\`.
- Server: assemble and return full package after access check (#16).

## Acceptance Criteria
- [ ] Server response includes everything recipient needs to verify + decrypt.
- [ ] Client writes decrypted file to \`client_<user>/downloads/\`.

## References
ARCHITECTURE.md §8 (download)"

create_issue "#18 Decryption + signature verification on receiver" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: client,points: 3" \
"## Goal
Receiver verifies sender's cert + origin signature, unwraps AES key, decrypts file.

## Implementation
- Verify sender cert against CA trust anchor.
- \`rsa_oaep_decrypt(my_priv, password, wrapped_key)\` -> AES key.
- \`aes_gcm_decrypt(aes_key, nonce, ciphertext, aad)\` -> plaintext.
- Recompute canonical struct, verify origin signature.

## Acceptance Criteria
- [ ] Any verification failure -> file NOT written; warning printed; non-zero exit.
- [ ] Tests cover: wrong AAD, tampered ciphertext, bad sender signature.

## References
ARCHITECTURE.md §8"

create_issue "#19 Replay enforcement — seen-nonces cache + timestamp window" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,points: 3" \
"## Goal
Wire \`server/replay.py:check_and_record\` into every state-changing handler.

## Implementation
- Every state-changing request (UPLOAD, DOWNLOAD, REVOKE, ACK) goes through replay check.
- Reject STALE if abs(now - timestamp) > 30s.
- Reject REPLAY if nonce was seen.

## Acceptance Criteria
- [ ] Integration test that replays a captured upload request -> server rejects.
- [ ] Stale timestamp test (>30s old) -> reject.

## References
ARCHITECTURE.md §7.8"

create_issue "#20 Audit logging — all security events, redacted" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,points: 2" \
"## Goal
Use \`common/logger.py\` everywhere; never log secrets.

## Implementation
- INFO: connection, upload accepted, download served, ACK.
- WARNING: auth failures, expired access, replay detected.
- ERROR: signature verification failures, malformed messages.
- NEVER: private keys, plaintext, session keys.
- Cert fingerprints redacted via \`logger.fingerprint(blob)\`.

## Acceptance Criteria
- [ ] grep -E '(BEGIN PRIVATE|password|session_key)' server/logs/audit.log returns nothing.
- [ ] Test that ensures sensitive values never appear in log output.

## References
ARCHITECTURE.md §9"

create_issue "#22b README — download, security analysis, division of labor" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,docs,points: 2" \
"## Goal
Finish README's remaining sections.

## Acceptance Criteria
- [ ] 'Secure Retrieval and Access Control' section (§5).
- [ ] 'File Expiration' section (§6).
- [ ] 'Security Analysis' — discusses ARCHITECTURE.md §12 limitations honestly.
- [ ] 'Division of Labor' — who did what, with PR references.

## References
README.md remaining (TODO) sections"

create_issue "#23 Integration test — PDF 11-step demo scenario" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,tests,points: 3" \
"## Goal
End-to-end test that walks the assignment PDF's demo steps.

## Implementation
- \`zerotrust/tests/test_integration.py\` (stub exists).
- Use pytest fixtures to spin up CA, server, two clients.
- Walk all 11 steps from the assignment PDF.

## Acceptance Criteria
- [ ] Single \`pytest -k integration\` runs the full demo green.
- [ ] Both happy path AND a malicious-server-style negative case covered.

## References
PDF assignment doc, ARCHITECTURE.md §8"

create_issue "#24 [BONUS] Revocation — REVOKE_REQUEST, status='revoked'" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,bonus,points: 2" \
"## Goal
Sender can revoke a pending file before recipient downloads.

## Implementation
- New REVOKE_REQUEST message with signature over revoke struct.
- Server verifies sender owns the file, then sets status='revoked'.
- Subsequent download attempts -> REVOKED error.

## Acceptance Criteria
- [ ] Only the original sender can revoke.
- [ ] Already-downloaded files cannot be revoked.

## References
ARCHITECTURE.md §8, §11"

create_issue "#25 [BONUS] One-time download — consume only after ACK" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,bonus,points: 3" \
"## Goal
Don't mark a file 'downloaded' until the recipient sends a signed ACK (#26).

## Implementation
- DOWNLOAD_RESPONSE doesn't change status.
- DOWNLOAD_ACK (#26) flips status to 'downloaded'.
- Second download attempt before ACK -> still served (network retry).
- After ACK -> ALREADY_DOWNLOADED error.

## Dependencies
Pair with #26.

## References
ARCHITECTURE.md §8 (bonus), §11"

create_issue "#26 [BONUS] Recipient ACK — signed DOWNLOAD_ACK" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: client,area: server,bonus,points: 2" \
"## Goal
After successful decrypt+verify, recipient signs a confirmation and sends DOWNLOAD_ACK.

## Implementation
- Client signs canonical \`{file_id, 'received', timestamp}\`.
- Server verifies with recipient's cert, stores in \`acks\` table.

## Acceptance Criteria
- [ ] ACK written to \`acks\` table.
- [ ] Forged ACK (wrong signer) rejected.

## Dependencies
Pair with #25.

## References
ARCHITECTURE.md §8 (bonus), §5"

create_issue "#27 Cleanup thread — old nonces, expired files" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,area: server,points: 2" \
"## Goal
Background thread runs every 60s.

## Implementation
- Delete \`seen_nonces\` rows where seen_at older than 5 minutes (already in \`server/replay.py\`).
- Mark \`files\` as 'expired' where expiration < now() AND status='pending'.

## Acceptance Criteria
- [ ] Cleanup loop survives server lifetime; logs each pass.
- [ ] Tests force-advance the clock and observe state transitions.

## References
ARCHITECTURE.md §6 (cleanup thread)"

create_issue "#28 Demo scenario files — sample inputs, test scripts, screenshots" \
"M3 — Download + Hardening + Bonus" \
"milestone-3,docs,points: 2" \
"## Goal
Make the demo reproducible by anyone (including the grader).

## Implementation
- \`demo/\` folder with: sample files, expected-output reference, screenshot of a successful run.
- \`demo/run_demo.sh\` orchestrates the 11-step flow.

## Acceptance Criteria
- [ ] Fresh clone + \`make install && bash demo/run_demo.sh\` works.
- [ ] At least one screenshot/asciinema embedded in README.

## References
PDF demo scenario"

echo
echo "Done. Open the repo on GitHub to verify."
echo "  -> https://github.com/$REPO/issues"
echo "  -> https://github.com/$REPO/milestones"
