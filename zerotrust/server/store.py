import os
import sqlite3
import time


def open_connection(db_path: str) -> sqlite3.Connection:
    # KURAL: Parent directory'nin var olduğundan emin ol
    if db_path != ":memory:":
        parent_dir = os.path.dirname(db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
            
    # KURAL: sqlite3.connect çağrısında detect_types=sqlite3.PARSE_DECLTYPES kullan
    # KURAL: Bağlantıyı ASLA global olarak cache'leme (Thread-safety)
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    # Sözlük benzeri row yapıları için row_factory ayarlanır
    conn.row_factory = sqlite3.Row
    return conn

def init_schema(conn: sqlite3.Connection) -> None:
    # KURAL: CREATE TABLE IF NOT EXISTS ve CREATE INDEX IF NOT EXISTS kullan
    schema = """
    CREATE TABLE IF NOT EXISTS files (
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
    CREATE INDEX IF NOT EXISTS idx_files_recipient ON files(recipient_id, status);

    CREATE TABLE IF NOT EXISTS seen_nonces (
        nonce      BLOB PRIMARY KEY,
        seen_at    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nonces_seen_at ON seen_nonces(seen_at);

    CREATE TABLE IF NOT EXISTS acks (
        file_id        TEXT PRIMARY KEY,
        ack_signature  BLOB NOT NULL,
        ack_timestamp  INTEGER NOT NULL
    );
    """
    with conn:
        conn.executescript(schema)

def insert_file(conn: sqlite3.Connection, row: dict) -> None:
    # KURAL: KESİNLİKLE string-format kullanma, ? (parameterized queries) kullan.
    query = """
        INSERT INTO files (
            file_id, sender_id, recipient_id, upload_timestamp, expiration, status, 
            ciphertext_path, ciphertext_sha256, wrapped_key, aes_nonce, aes_aad, 
            sender_signature, sender_cert_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    # KURAL: status değeri verilmemişse varsayılan olarak 'pending' ata.
    status = row.get('status', 'pending')
    
    values = (
        row['file_id'],
        row['sender_id'],
        row['recipient_id'],
        row['upload_timestamp'],
        row['expiration'],
        status,
        row['ciphertext_path'],
        row['ciphertext_sha256'],
        row['wrapped_key'],  # KURAL: Doğrudan bytes nesnesi bekleniyor
        row['aes_nonce'],    # KURAL: Doğrudan bytes nesnesi bekleniyor
        row['aes_aad'],      # KURAL: Doğrudan bytes nesnesi bekleniyor
        row['sender_signature'], # KURAL: Doğrudan bytes nesnesi bekleniyor
        row['sender_cert_json']
    )
    
    # KURAL: Transaction yönetimi için with conn kullan
    with conn:
        conn.execute(query, values)

def list_pending_for(conn: sqlite3.Connection, recipient: str) -> list[dict]:
    # KURAL: Sadece status='pending' olan ve expiration > int(time.time()) olanları getir
    query = """
        SELECT * FROM files 
        WHERE recipient_id = ? AND status = 'pending' AND expiration > ?
    """
    now = int(time.time())
    cursor = conn.cursor()
    cursor.execute(query, (recipient, now))
    return [dict(row) for row in cursor.fetchall()]

def get_file(conn: sqlite3.Connection, file_id: str) -> dict | None:
    query = "SELECT * FROM files WHERE file_id = ?"
    cursor = conn.cursor()
    cursor.execute(query, (file_id,))
    row = cursor.fetchone()
    if row:
        return dict(row)
    return None

def mark_status(conn: sqlite3.Connection, file_id: str, status: str) -> None:
    # KURAL: Gelen status değerinin tuple içinde olup olmadığını doğrula
    valid_statuses = ('pending', 'downloaded', 'expired', 'revoked')
    if status not in valid_statuses:
        raise ValueError(f"Geçersiz status: '{status}'. İzin verilenler: {valid_statuses}")

    query = "UPDATE files SET status = ? WHERE file_id = ?"
    # KURAL: Transaction yönetimi için with conn kullan
    with conn:
        conn.execute(query, (status, file_id))


def mark_expired(conn: sqlite3.Connection, *, now: int | None = None) -> int:
    """Mark every still-pending file whose expiration has passed as 'expired'.

    Used by the background cleanup thread (ARCHITECTURE.md §6, issue #27).
    Only rows where ``status='pending' AND expiration < now`` are touched —
    rows already 'downloaded' / 'expired' / 'revoked' are left alone so
    audit history is preserved.

    Args:
        conn: Thread-local sqlite3 connection (AI.md §5 — never shared).
        now: Override the current time. Defaults to ``int(time.time())``.
            Tests force-advance the clock by passing this explicitly.

    Returns:
        Number of rows that flipped to 'expired' in this pass.
    """
    cutoff = int(now) if now is not None else int(time.time())
    query = (
        "UPDATE files SET status = 'expired' "
        "WHERE status = 'pending' AND expiration < ?"
    )
    with conn:
        cur = conn.execute(query, (cutoff,))
        return cur.rowcount
