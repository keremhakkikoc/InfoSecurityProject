# ZeroTrust Demo UI

A thin Flask wrapper around the existing CLI for class-presentation
purposes. It does **not** reimplement any part of the protocol — every
action shells out to `python -m zerotrust.client.cli`, so the real
handshake, AES-GCM AAD binding, RSA-PSS origin signature, replay cache,
and server-side chokepoint are all still in the call path.

## Run it (3 terminals)

Each terminal: `cd` into the repo and `source venv/bin/activate`.

```bash
# Terminal 1 — one-shot bootstrap (CA + server cert + alice + bob)
make demo-setup

# Terminal 1 — start the protocol server
make server

# Terminal 2 — start the web UI
pip install -r webui/requirements.txt
make webui
```

Open <http://127.0.0.1:8000>. The header has an **+ Add user** form so
you can mint additional identities (charlie, dave, …) live during the
demo — each one runs `make user USER=<name>` which does
`ca-issue` + `client-setup` + `server-register` in one shot.

Two dropdowns at the top of each column let you switch which user is
acting (sender) and whose inbox you're viewing (recipient). The
**Recent commands** panel below the columns shows the exact subprocess
that fired for each click — useful to show graders "this button
actually ran `python -m zerotrust.client.cli ...`".

The collapsible **Server inspect** panel at the bottom mirrors
`make inspect`: registered pubkeys, file metadata rows, and ciphertext
blob sizes.

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
