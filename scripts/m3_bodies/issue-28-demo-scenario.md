## Goal
Make the demo reproducible by anyone — including the grader on grading day — without typing more than two commands. Adds `demo/` folder with sample inputs, an end-to-end runner script, and at least one screenshot/asciinema of a successful run.

## Why this matters
The 11-step PDF demo is what gets graded. If it relies on undocumented setup, the grader will mark it as "didn't run" and there's no way to dispute it later. A scripted demo is a one-line proof.

## Dependencies
- **Blocked by:** all of M2 + #17 + #18 in M3 (the bytes have to actually flow).

## Files you will create
| Path | Purpose |
|---|---|
| `demo/run_demo.sh` | Bash orchestrator. Bootstraps CA, issues alice + bob, starts server in background, runs Alice upload, runs Bob download, asserts plaintext match, shuts server down cleanly. Returns exit 0 on success. |
| `demo/sample_files/` | One or two sample files Alice uploads. Keep them small (≤ 100 KB) and innocuous. |
| `demo/expected_output.txt` | Reference output the runner can diff against (`Upload successful`, `Download successful`, `Plaintext match`). |
| `demo/README.md` | Two paragraphs explaining what the demo does and how to inspect the result. Links back to the main README's Section 5. |
| `demo/screenshot.png` (or `demo/demo.cast`) | A captured run for the main README to embed. |

## What `demo/run_demo.sh` does
```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Clean slate
make clean
make install
# 2. CA + identities
make ca-init
make ca-issue USER=alice
make ca-issue USER=bob
# 3. Client bundles + server registration
make client-setup USER=alice
make client-setup USER=bob
make server-register USER=alice
make server-register USER=bob
# 4. Server in background
python -m zerotrust.server.main --port 5050 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1
# 5. Alice uploads
python -m zerotrust.client.cli --user alice login
FILE_ID=$(python -m zerotrust.client.cli --user alice upload bob demo/sample_files/report.pdf | tail -1 | awk '{print $2}')
# 6. Bob lists + downloads
python -m zerotrust.client.cli --user bob list
python -m zerotrust.client.cli --user bob download "$FILE_ID"
# 7. Verify plaintext match
diff demo/sample_files/report.pdf client_bob/downloads/report.pdf
echo "Plaintext match — demo OK"
```

(Adjust to whatever the real `cli.py` arg shape ends up being.)

## Acceptance criteria
- [ ] Fresh clone + `make install && bash demo/run_demo.sh` returns exit 0.
- [ ] Demo runs in under 30 seconds on a developer laptop.
- [ ] `demo/expected_output.txt` matches the live runner output (ignoring timestamps).
- [ ] At least one screenshot or asciinema embedded in the main README's Section 5.
- [ ] If demo fails midway (e.g. port collision), `trap` ensures the server is killed — no zombie process.

## Required tests
The CI doesn't need to run the full demo (slow + needs background process). Instead, add a `tests/test_demo_script.py` that:
- Checks `demo/run_demo.sh` exists and is executable.
- Lints it with `bash -n` for syntax.
- Reads it and asserts it references the expected `make` targets (`ca-init`, `ca-issue`, `client-setup`, `server-register`) — guards against silent drift if those Makefile targets get renamed.

## Pitfalls — DO NOT do these
- ❌ **DO NOT** ship real / private files in `demo/sample_files/`. Use `head -c 4096 /dev/urandom > report.pdf`-style filler or a placeholder text file.
- ❌ **DO NOT** hard-code absolute paths. Everything relative to repo root.
- ❌ **DO NOT** rely on user-installed tools beyond what `make install` provides. If you need `jq` or `bc`, install them in the script or avoid them.
- ❌ **DO NOT** leave the server process running on failure. The `trap` is non-negotiable.
- ❌ **DO NOT** commit generated artifacts (`ca_data/`, `users/`, `client_*/`, `server/storage/`). They're already in `.gitignore`; `make clean` strips them at the start.

## References
- The PDF demo scenario (11 steps)
- `Makefile` targets `ca-init`, `ca-issue`, `client-setup`, `server-register`, `inspect`
- README Section 5 (which will embed the screenshot)
