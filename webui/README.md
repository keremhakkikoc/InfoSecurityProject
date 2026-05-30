# ZeroTrust Demo UI

A thin Flask wrapper around the existing CLI for class-presentation
purposes. It does **not** reimplement any part of the protocol — every
action shells out to `python -m zerotrust.client.cli`, so the real
handshake, AES-GCM AAD binding, RSA-PSS origin signature, replay cache,
and server-side chokepoint are all still in the call path.

## Run it

Assumes the CA + identities are already bootstrapped and the server is
already running (i.e. you've done the bootstrap section of the main
README, then `python -m zerotrust.server.main`).

```bash
source venv/bin/activate
pip install -r webui/requirements.txt
python webui/app.py
```

Then open <http://127.0.0.1:8000>. Left column is Alice (sender), right
column is Bob (recipient). The collapsible "Server inspect" panel at the
bottom shows the same data as `make inspect`.

## What you can demo

- Alice uploads a file to Bob (multipart form).
- Bob's inbox lists pending files; click Download to retrieve.
- Alice revokes a still-pending file.
- The inspect panel proves the server stores ciphertext only — try
  `cat zerotrust/server/storage/files/<blob>` to see the random bytes.

## Security caveats (don't ship this)

- `app.secret_key = "demo-secret"` — flash messages only, no auth on
  the UI; anyone reaching the port acts as both Alice and Bob.
- Uses the documented `demo-password` for every CLI call via
  `ZEROTRUST_USER_PASSWORD`.
- Binds to `127.0.0.1` only on purpose.
