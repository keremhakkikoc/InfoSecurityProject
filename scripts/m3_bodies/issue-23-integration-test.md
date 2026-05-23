## Goal
A single pytest test that walks the assignment PDF's 11-step demo end-to-end: CA bootstrap → issue Alice + Bob → start server → Alice logs in → Alice uploads → Bob logs in → Bob lists pending → Bob downloads → Bob verifies + decrypts → file on disk matches original. Plus the headline negative case: a malicious server (or in-flight tampering) is detected before any forged plaintext lands.

## Why this matters
Unit tests prove each piece in isolation. This proves they compose. If this is green, the demo on grading day will be green.

## Dependencies
- **Blocked by:** everything in M2 + #15, #16, #17, #18 in M3.

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/tests/test_integration.py` | Replace any stub with the real 11-step walk. Two test functions: `test_pdf_demo_happy` and `test_pdf_demo_tampering_rejected`. |
| (optional) `demo/` | If we go that route in #28, the integration test can shell-out to `bash demo/run_demo.sh` for parity with the live demo. |

## What the test asserts, step by step
1. Fresh `tmp_path` workspace; `python -m zerotrust.ca.ca init` writes `ca_data/`.
2. `make ca-issue USER=alice` and `make ca-issue USER=bob` produce `users/<name>/{cert.json, private.pem, public.pem}`.
3. `make server-register USER=alice` and `... bob` populate `server/storage/pubkeys/`.
4. Server thread starts on an ephemeral port; assert it's listening within 1s.
5. Alice's client connects, performs `perform_client_handshake`; session dict has the frozen shape.
6. Alice's client uploads `report.pdf` (4 KB random bytes) for Bob; receives `UPLOAD_ACK` with a `file_id`.
7. Bob's client connects, performs handshake.
8. Bob's `LIST_PENDING` returns exactly one row with the right `file_id`.
9. Bob's `DOWNLOAD_REQUEST` for that file_id receives `DOWNLOAD_RESPONSE`.
10. `verify_and_decrypt_download` returns plaintext == original 4 KB blob.
11. `make inspect` shows the row with `status='pending'` (or `'downloaded'` if bonus #25 wired); blob present on disk; `pubkeys/` contains both users.

Negative test:
- Same up to step 9, but the test intercepts the `DOWNLOAD_RESPONSE` payload, flips one byte of `payload["ciphertext"]` (base64-then-modify), and feeds it to `verify_and_decrypt_download`. Asserts `CryptoError` raised, no file written.

## Acceptance criteria
- [ ] `pytest -k integration` runs both tests green in under 10 seconds.
- [ ] Happy test exercises every M2+M3 entry point at least once: handshake, GET_PUBKEY, UPLOAD_REQUEST, LIST_PENDING, DOWNLOAD_REQUEST, verify_and_decrypt.
- [ ] Tampering test confirms the recipient detects a corrupt payload before plaintext lands.
- [ ] No `tmp_path` leakage; each test cleans up its own server thread on teardown.

## Required tests
- `test_pdf_demo_happy` — described above.
- `test_pdf_demo_tampering_rejected` — described above.
- (Bonus, if time) `test_pdf_demo_unknown_recipient` — Alice tries to upload to `mallory` who isn't registered → `NOT_FOUND` from upload handler.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** mock `perform_server_handshake` or `verify_certificate`. The whole point of an integration test is that the *real* primitives compose. Mocking defeats it. **Past mistake (#13):** Kerem's "test_server_upload.py" mocked `verify_origin_struct` with a stub that always returned True — passed the test, missed the bug.
- ❌ **DO NOT** hard-code port 5050. Use `bind(("127.0.0.1", 0))` and read the assigned port back. CI runs in parallel; fixed ports collide.
- ❌ **DO NOT** assert string equality on log output ("Authenticated as alice"). Strings drift; assert on **structured side effects** (file exists, row in DB, key material matches).
- ❌ **DO NOT** let the server thread outlive the test. Always `server.shutdown()` + `t.join(timeout=2.0)` in `finally`.
- ❌ **DO NOT** use `time.sleep(N)` to wait for the server to be ready. Use a `socket.create_connection` retry loop with a timeout, or a `threading.Event` the server sets after bind.

## References
- The assignment PDF — the 11-step demo scenario
- ARCHITECTURE.md §8 (lifecycle — gives the test its order)
- `Makefile` targets (`ca-init`, `ca-issue`, `client-setup`, `server-register`, `inspect`) — the test can shell out to these or call the equivalent Python directly
