# Reproducible Demo

Run `bash demo/run_demo.sh` from the repository root after `make install`. The
script starts from a clean state, bootstraps the CA, issues demo identities for
`server`, `alice`, and `bob`, registers Alice and Bob with the server, starts
the server in the background, uploads `demo/sample_files/report.txt` from Alice
to Bob, downloads it as Bob, and verifies the plaintext bytes match.

The runner writes a stable transcript that is diffed against
`demo/expected_output.txt`; dynamic values such as UUID file IDs and expiration
timestamps are checked internally instead of being printed. The captured demo
artifacts are `demo/screenshot.png` and `demo/demo.cast`, and the main README
embeds the screenshot in
[Section 5](../README.md#section-5--reproducible-demo).
