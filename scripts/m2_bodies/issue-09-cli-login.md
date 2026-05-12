## Goal
Provide `python -m zerotrust.client.cli --user <name> login` that connects to the server, performs the handshake, and prints a success banner.

## Why this matters
Every other client command (`upload`, `list`, `download`) is going to need a logged-in session. This issue establishes the **session bootstrap path** the rest of the CLI reuses.

## Dependencies
- **Blocked by:** #8 (handshake must work end-to-end).
- **Pairs with:** #12 (upload CLI extends the same `cli.py`).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/client/cli.py` | Replace `NotImplementedError` with `argparse` dispatcher. |
| `zerotrust/client/session.py` | **NEW** — small helper that loads user assets and calls `perform_client_handshake`. |
| `zerotrust/tests/test_client_cli.py` | **NEW** — argparse-level smoke tests (mock the handshake). |

## Client storage layout (ARCHITECTURE.md §4.2)
```
client_<username>/
├── ca_cert.json          # CA trust anchor (manually distributed)
├── private.pem           # password-encrypted
├── cert.json             # this user's CA-signed cert
└── config.json           # { "server_host": "...", "server_port": ..., "username": "..." }
```

## Implementation steps
1. Argparse:
   ```
   python -m zerotrust.client.cli --user alice login
                                  --user alice upload <recipient> <file>   # M2 #12
                                  --user alice list                         # M3 #15
                                  --user alice download <file_id>           # M3 #17
   ```
2. Read `client_<user>/config.json` for `server_host` and `server_port`.
3. Get the user's password: priority `--password` arg > env var `ZEROTRUST_USER_PASSWORD` > prompt with `getpass.getpass()`. Match the CA CLI's pattern.
4. Load `cert.json`, `private.pem` bytes, `ca_cert.json` (extract `public_key_pem`).
5. Open `socket.create_connection((host, port))`, call `perform_client_handshake(...)`.
6. On success: print `Authenticated as <username>; session established with <server_subject>.` Exit 0.
7. On any failure: print generic `AUTH_FAILED` to stderr, exit 1. **Never leak the underlying reason** (AI.md §4.36).

## Acceptance criteria
- [ ] `python -m zerotrust.client.cli --user alice login` connects to a running server and prints the success line.
- [ ] Wrong password → exits 1 with `AUTH_FAILED`. No stack trace.
- [ ] Server down → exits 1 with a clean `connection refused` message (acceptable to expose this; not a security leak).
- [ ] Missing `cert.json` or `private.pem` → clear error: `client_alice/cert.json not found`.
- [ ] No private key material printed to stdout/stderr anywhere.

## Required tests
- `argparse` accepts the documented command shapes.
- Missing required arg (`--user`) → exits 2.
- With the handshake mocked, login command calls it with the right paths.

## Pitfalls
- Do NOT print stack traces on auth failures — `AUTH_FAILED` should be terse. Use `try/except CryptoError as exc: sys.exit("AUTH_FAILED")`.
- Do NOT cache the password to disk for "convenience" — only in-memory for the lifetime of the command.
- The `--user` arg controls **which directory** to load from; `--password` controls the **decryption password**. Two different things.

## References
- ARCHITECTURE.md §4.2 (client storage layout)
- AI.md §3.10 (password handling)
- AI.md §4 (generic error responses to clients)
