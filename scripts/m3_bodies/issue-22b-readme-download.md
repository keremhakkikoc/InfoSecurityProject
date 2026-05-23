## Goal
Finish README.md sections 5 ("Secure Retrieval and Access Control"), 6 ("File Expiration"), 7 ("Security Analysis"), and add a "Division of Labor" section. Replace any `(TODO)` placeholders left from #22a.

## Why this matters
The grader reads README first. M2's #22a covered handshake + upload narrative; this PR closes the loop with download + retention + an honest threat-model discussion + who-did-what.

## Dependencies
- **Blocked by:** download path (#17, #18), access checks (#16), expiration cleanup (#27) being merged so the prose describes real, working code.

## Files you will touch
| Path | Change |
|---|---|
| `README.md` | Sections 5, 6, 7 rewritten with prose. New "Division of Labor" section near the end. |

## What each section should contain

### Section 5 — Secure Retrieval and Access Control
- One paragraph on the LIST_PENDING / DOWNLOAD_REQUEST round trip.
- One paragraph on the chokepoint authorisation (#16): why `peer_subject` not `payload["recipient"]`, how `NOT_AUTHORIZED` / `EXPIRED` / `REVOKED` map.
- One paragraph on the recipient's verify-then-decrypt order (#18): cert → signature → unwrap → AES-GCM. **Mention the AAD binding** — that's the bit that defeats server-side ciphertext substitution.
- Demo block: the three-terminal flow ending with `download <file_id>` producing the file in `client_bob/downloads/`.

### Section 6 — File Expiration
- The 30-second freshness window for envelope nonces (replay) vs. the per-file `expiration` field (retention) — two different clocks, both real.
- The cleanup thread (#27): purges `seen_nonces` older than 5 minutes, marks files `'expired'` when `expiration < now()`. Mention it runs every 60 seconds.
- Why expiration alone isn't enough without `mark_status('expired')` — a stale row sitting in the table doesn't fail-close unless something updates its status.

### Section 7 — Security Analysis
Be honest. Cover at least:
- **Threat model:** what the server CAN see (sender, recipient, file size, timing), what it CAN'T (plaintext, AES key).
- **Defended:** identity substitution (mutual PoP), replay (envelope nonce cache), ciphertext substitution (AAD), forward integrity (origin signature binding ciphertext hash + wrapped key hash).
- **NOT defended (documented limitations from ARCHITECTURE.md §12):** no forward secrecy (RSA long-term key compromise re-decrypts past sessions), no traffic-analysis resistance, manual CA bootstrap, password-protected PEMs with demo password in config.
- One sentence on what would need to change for production (ECDHE for FS, OS keychain for keys, real CRL or short-lived certs).

### Section "Division of Labor"
Three short subsections (Alp / Kerem / Turgut), each with:
- Issues owned (with PR links if useful)
- Notable contributions
- Number of commits / PRs

Don't editorialise. Just facts the grader can verify from `git log --author=...`.

## Acceptance criteria
- [ ] No `(TODO)` in README.
- [ ] Sections 5, 6, 7 each 150–400 words. Concise, not lecture-style.
- [ ] Each section references the relevant ARCHITECTURE.md anchor.
- [ ] At least one screenshot or terminal capture in the demo block (asciinema or just a fenced code block of actual output).
- [ ] "Division of Labor" present and accurate.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** paraphrase ARCHITECTURE.md. README is grader-facing narrative; ARCHITECTURE is the technical spec. Link, don't duplicate.
- ❌ **DO NOT** oversell. If forward secrecy isn't there, say so. The grader will know if you claim a property the code doesn't have.
- ❌ **DO NOT** include real keys, real passwords, or real file contents in the README screenshots. Use `report.pdf` placeholders and the documented `demo-password`.
- ❌ **DO NOT** write the "Division of Labor" from memory — use `git log --pretty=format:'%an %s' | sort -k1` to get the real attribution.

## References
- README.md sections 5, 6, 7 (currently TODO or partial)
- ARCHITECTURE.md §12 (known limitations — copy the bullets verbatim into Security Analysis)
- ARCHITECTURE.md §8 (file lifecycle — diagram for Section 5)
