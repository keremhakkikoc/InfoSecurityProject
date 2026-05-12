## Goal
Implement `server/store.py` with the exact SQLite schema from ARCHITECTURE.md §5, plus the CRUD helpers Phase 2/3 will call.

## Why this matters
Every other server-side issue depends on this. No metadata = no list, no download, no expiration, no revocation. Build it early so others don't sit on stubs.

## Dependencies
- **Blocked by:** none. Can start day 1.
- **Used by:** #13 (insert), #15 (list pending), #16 (lookup + status), #17 (full row fetch), #19 (`seen_nonces`), #24 (revoke), #25 (one-time), #26 (acks), #27 (cleanup).

## Files you will touch
| Path | Change |
|---|---|
| `zerotrust/server/store.py` | Replace `NotImplementedError` stubs with real bodies. |
| `zerotrust/tests/test_store.py` | **NEW** — schema, insert, list, get, mark_status. |

## Schema (ARCHITECTURE.md §5 — VERBATIM)
```sql
CREATE TABLE files (
    file_id           TEXT PRIMARY KEY,
    sender_id         TEXT NOT NULL,
    recipient_id      TEXT NOT NULL,
    upload_timestamp  INTEGER NOT NULL,
    expiration        INTEGER NOT NULL,
    status            TEXT NOT NULL,            -- 'pending'|'downloaded'|'expired'|'revoked'
    ciphertext_path   TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    wrapped_key       BLOB NOT NULL,
    aes_nonce         BLOB NOT NULL,
    aes_aad           BLOB NOT NULL,
    sender_signature  BLOB NOT NULL,
    sender_cert_json  TEXT NOT NULL
);
CREATE INDEX idx_files_recipient ON files(recipient_id, status);

CREATE TABLE seen_nonces (
    nonce      BLOB PRIMARY KEY,
    seen_at    INTEGER NOT NULL
);
CREATE INDEX idx_nonces_seen_at ON seen_nonces(seen_at);

CREATE TABLE acks (
    file_id        TEXT PRIMARY KEY,
    ack_signature  BLOB NOT NULL,
    ack_timestamp  INTEGER NOT NULL
);
```

The `seen_nonces` table is shared with `server/replay.py`. Make sure schema creation is idempotent (`CREATE TABLE IF NOT EXISTS`).

## Frozen function bodies to fill
```python
def open_connection(db_path: str) -> sqlite3.Connection: ...
def init_schema(conn: sqlite3.Connection) -> None: ...
def insert_file(conn: sqlite3.Connection, row: dict) -> None: ...
def list_pending_for(conn: sqlite3.Connection, recipient: str) -> list[dict]: ...
def get_file(conn: sqlite3.Connection, file_id: str) -> dict | None: ...
def mark_status(conn: sqlite3.Connection, file_id: str, status: str) -> None: ...
```

Use parameterised queries (`?` placeholders), never string-formatted SQL.

## Implementation steps
1. `open_connection(db_path)`: ensure parent dir exists, return `sqlite3.connect(db_path)` with `detect_types=sqlite3.PARSE_DECLTYPES` if helpful. **Do NOT cache** — caller owns lifetime.
2. `init_schema`: executescript the schema above. Idempotent.
3. `insert_file`: validate `row` has every required field, then INSERT. Status defaults to `'pending'` if absent.
4. `list_pending_for`: `SELECT ... WHERE recipient_id=? AND status='pending' AND expiration > ?` — pass `int(time.time())` for expiration cutoff so expired rows are filtered.
5. `get_file`: `SELECT ... WHERE file_id = ? LIMIT 1`. Return None if not found.
6. `mark_status`: validate `status` is in the allowed set (`pending|downloaded|expired|revoked`) then UPDATE.

## Acceptance criteria
- [ ] `init_schema` is idempotent (calling twice doesn't error).
- [ ] Insert → list → get → mark_status flow works in one test.
- [ ] `list_pending_for("alice")` does NOT return rows where `recipient_id != "alice"`.
- [ ] `list_pending_for("bob")` does NOT return expired rows.
- [ ] `mark_status(conn, ..., "not_a_real_status")` raises ValueError.
- [ ] Schema is byte-exact match with ARCHITECTURE.md §5 (paste-compare).

## Required tests
- Schema creation idempotent.
- Insert / fetch round-trip preserves all 13 columns bit-for-bit.
- Recipient isolation (Alice can't see Bob's rows).
- Expired filter.

## Pitfalls
- Each thread opens its own connection. **DO NOT** cache connections in module globals — sqlite3 connections are not thread-safe by default.
- BLOB columns (`wrapped_key`, `aes_nonce`, `sender_signature`) take **bytes** in Python, not str. Make sure you pass `bytes` not base64 strings.
- Use `with conn:` for write transactions so commits / rollbacks happen automatically.
- `sender_cert_json` is the JSON string of the cert, not a parsed dict — store the string verbatim so signature verification can recompute on retrieval.
- Don't add columns that aren't in §5 without an architecture update.

## References
- ARCHITECTURE.md §5 (SQLite Schema)
- ARCHITECTURE.md §6 (per-thread connections)
