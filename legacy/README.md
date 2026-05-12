# Legacy / Phase 0 Prototype

These files are the original prototype written before `ARCHITECTURE.md` was
frozen. They use **X.509** certificates and a flat module layout, neither of
which match the design now in `ARCHITECTURE.md` (custom JSON certs, modular
`zerotrust/` package).

They are kept here for reference only — useful as a working example of the
RSA-OAEP + HKDF handshake — and are NOT imported or tested by the new
package. Once the equivalent functionality lands in `zerotrust/server/` and
`zerotrust/client/` during Phase 2, this directory can be deleted.

| File | Replaced by |
|---|---|
| `ca_x509.py` | `zerotrust/ca/ca.py` + `zerotrust/ca/cert.py` |
| `server_x509.py` | `zerotrust/server/{main,handler,handshake}.py` (Phase 2) |
| `client_x509.py` | `zerotrust/client/{cli,handshake,upload,download}.py` (Phase 2) |
| `certs/` | `ca_data/` + `users/<username>/` produced by `python -m zerotrust.ca.ca` |
