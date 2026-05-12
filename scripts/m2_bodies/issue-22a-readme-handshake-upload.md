## Goal
Update README.md sections 2 (handshake), 3 (encryption + upload), 4 (signature) with prose explaining the **M2 implementation** — replacing the existing (TODO) placeholders.

## Why this matters
The grader reads the README first. Right now sections 2-4 say "(TODO)". By the time M2 closes we need a coherent narrative grading wants to see: how we did the handshake, what's encrypted with what, what's signed by whom.

## Dependencies
- **Blocked by:** the M2 work being mostly merged so you can describe what actually exists, not what's planned.
- Should land in the **last PR of M2**, after #5/#8/#12/#13 are merged.

## Files you will touch
| Path | Change |
|---|---|
| `README.md` | Sections 2, 3, 4 rewritten with real prose. |

## What each section should contain

### Section 2 — Secure Handshake and Session Key Establishment
- Diagram (ASCII or mermaid) of the 5-step ladder: HELLO ↔, KEY_EXCHANGE, AUTH_RESPONSE, SESSION_OK.
- 2-3 sentences per step explaining **what is sent** and **what is verified**.
- Call out: mutual PoP, transcript hash binding, HKDF over `nonce_c || nonce_s`.
- 1 sentence on why we don't use TLS: the assignment forbids pre-built secure channel libraries; we hand-rolled exactly the parts TLS would have done.

### Section 3 — Secure File Encryption and Upload
- A fresh AES-256-GCM key per file.
- AAD binding `f"{file_id}|{sender}|{recipient}"` — explain why this stops ciphertext-substitution attacks.
- The wrapped-key construction (RSA-OAEP under recipient's pubkey) — server never sees the AES key.
- Where the ciphertext lives on disk; reference the SQLite schema (§5) for metadata.

### Section 4 — Digital Signature and Integrity Verification
- The canonical origin struct (paste the 7 fields).
- Why we bind BOTH `ciphertext_sha256` AND `wrapped_key_sha256` (defeats server-side component substitution).
- RSA-PSS over canonical JSON — emphasise canonical encoding (sort_keys, compact separators).
- Where the sig is verified: at the server (#13) and at the recipient on download (#18, M3).

## Acceptance criteria
- [ ] Sections 2, 3, 4 have no "(TODO)" left.
- [ ] Each section is 150–300 words. Not 50 (too terse), not 1000 (drowning).
- [ ] Each section references the relevant ARCHITECTURE.md anchor (e.g., `§7.4`, `§7.6`, `§7.7`).
- [ ] At least one demo command shown — e.g., the 3-terminal upload flow from #12's body.
- [ ] Spell-check + a quick read-through by another team member.

## Tone
Aim for "competent senior reviewing your decisions" — describe what you chose AND why. Mention rejected alternatives where it adds clarity ("RSA over ECC to keep one crypto stack", "GCM instead of CBC+HMAC to get AEAD in one step").

## Pitfalls
- Don't paraphrase ARCHITECTURE.md — the README is for grader-facing narrative. Architecture is the technical spec. Link, don't duplicate.
- Keep secrets out: don't print example plaintexts that look like they could be real.
- If you copy the canonical struct from §7.6, make sure the field list matches what #11b actually signs.

## References
- README.md (the file you're editing)
- ARCHITECTURE.md §7.4–§7.7
- The actual PRs that landed for #5–#14 (link to them — graders can follow)
