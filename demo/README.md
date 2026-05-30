# Demo scenario

This folder packages the 11-step PDF demo as a single reproducible script.
A fresh clone plus two commands is enough to see Alice encrypt and upload a
file, Bob list and download it, and the runner assert that the recovered
plaintext byte-matches the original. The orchestrator (`run_demo.sh`)
bootstraps the CA, issues `server`/`alice`/`bob` identities, registers
recipient pubkeys with the server, starts the server in the background,
and tears the server down on exit (including on failure) via a `trap`.

To run it:

```bash
make install
bash demo/run_demo.sh
```

The recovered file lands at `client_bob/downloads/<file_id>`. Compare the
runner's terminal output against `expected_output.txt` (timestamps,
PIDs, and the random `file_id`/`expires` UUIDs will differ — the
**structure** of each line and the final `Plaintext match — demo OK`
banner are the stable part). The captured screenshot used in the main
README's Section 5 lives at `demo/screenshot.png`.

The sample file at `sample_files/report.pdf` is a 4 KB random filler
generated with `head -c 4096 /dev/urandom > demo/sample_files/report.pdf`
— it is intentionally not a real PDF; the demo only needs a byte stream
to prove the encryption/decryption round-trip. Replace it with any small
file (≤ 100 KB) if you want a more realistic payload. The runner relies
only on byte-level equality, not file type.
