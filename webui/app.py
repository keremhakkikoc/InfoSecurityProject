"""Flask wrapper around the zerotrust CLI for demo / class presentation.

This is a thin UI: it does NOT reimplement the protocol. Every action
(upload, list, download, revoke) is performed by shelling out to the
existing ``python -m zerotrust.client.cli`` so the real handshake,
AAD-bound AES-GCM, RSA-PSS origin signature, replay cache, and server
chokepoint are all still in the call path. The UI is purely a thin
window into that flow.

The Flask server is assumed to run on the same machine as the user's
client_<user>/ bundles and the zerotrust server (``python -m
zerotrust.server.main``). It uses the documented demo password
(``demo-password``) via the ``ZEROTRUST_USER_PASSWORD`` env var so the
CLI doesn't pop interactive prompts.

Not production: trusts localhost, no auth on the Flask side, uses
``app.secret_key='demo-secret'``. The class demo, not the protocol, is
what this file ships.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_STORAGE = REPO_ROOT / "zerotrust" / "server" / "storage"
PUBKEYS_DIR = SERVER_STORAGE / "pubkeys"
METADATA_DB = SERVER_STORAGE / "metadata.db"
BLOBS_DIR = SERVER_STORAGE / "files"
UPLOADS_DIR = REPO_ROOT / "webui" / ".uploads"
DEMO_PASSWORD = "demo-password"

app = Flask(__name__)
app.secret_key = "demo-secret-not-for-prod"  # noqa: S105 — demo only


# ---------------------------------------------------------------------------
# CLI subprocess helper
# ---------------------------------------------------------------------------

def run_cli(user: str, *args: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run ``python -m zerotrust.client.cli --user <user> <args>``.

    Returns (returncode, stdout, stderr). The demo password is injected
    via env var so the CLI never blocks on getpass.
    """
    env = os.environ.copy()
    env["ZEROTRUST_USER_PASSWORD"] = DEMO_PASSWORD
    # Match the venv python that's running this Flask process.
    cmd = [sys.executable, "-m", "zerotrust.client.cli", "--user", user, *args]
    proc = subprocess.run(  # noqa: S603 — args are not shell-interpreted
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_list_output(stdout: str) -> list[dict[str, str]]:
    """Parse CLI list output lines into structured dicts.

    Line shape (from cmd_list in client/cli.py):
        ``<file_id> sender=<u> size=<n> expires=<unix_ts>``
    """
    rows: list[dict[str, str]] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        row: dict[str, str] = {"file_id": parts[0]}
        for kv in parts[1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                row[k] = v
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Read-only server-state introspection (mirrors `make inspect`).
# ---------------------------------------------------------------------------

def inspect_state() -> dict:
    state: dict = {"pubkeys": [], "files": [], "blobs": []}

    if PUBKEYS_DIR.is_dir():
        state["pubkeys"] = sorted(p.stem for p in PUBKEYS_DIR.iterdir() if p.is_file())

    if METADATA_DB.is_file():
        conn = sqlite3.connect(str(METADATA_DB))
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT file_id, sender_id, recipient_id, status, "
                "upload_timestamp, expiration "
                "FROM files ORDER BY upload_timestamp DESC"
            )
            state["files"] = [dict(r) for r in cur.fetchall()]
        except sqlite3.OperationalError:
            # Table may not exist on a freshly-bootstrapped server.
            state["files"] = []
        finally:
            conn.close()

    if BLOBS_DIR.is_dir():
        state["blobs"] = sorted(
            ({"name": p.name, "size": p.stat().st_size}
             for p in BLOBS_DIR.iterdir() if p.is_file()),
            key=lambda r: r["name"],
        )
    return state


def alice_sent(state: dict) -> list[dict]:
    return [f for f in state["files"] if f["sender_id"] == "alice"]


def bob_pending() -> tuple[list[dict[str, str]], str | None]:
    """Try to fetch Bob's pending inbox via the real CLI list path."""
    rc, out, err = run_cli("bob", "list")
    if rc != 0:
        msg = (err or out).strip() or f"list exited {rc}"
        return [], msg
    return parse_list_output(out), None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    state = inspect_state()
    pending, list_err = bob_pending()
    return render_template(
        "index.html",
        state=state,
        sent_by_alice=alice_sent(state),
        pending=pending,
        list_err=list_err,
    )


@app.route("/upload", methods=["POST"])
def upload():
    sender = request.form.get("sender", "alice").strip() or "alice"
    recipient = request.form.get("recipient", "bob").strip() or "bob"
    fp = request.files.get("file")
    if fp is None or not fp.filename:
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    # Strip any path components the browser may have included.
    safe_name = Path(fp.filename).name
    save_path = UPLOADS_DIR / safe_name
    fp.save(str(save_path))

    rc, out, err = run_cli(sender, "upload", recipient, str(save_path))
    if rc == 0:
        flash(out.strip(), "ok")
    else:
        flash(f"Upload failed: {(err or out).strip()}", "error")
    return redirect(url_for("index"))


@app.route("/download/<file_id>")
def download(file_id: str):
    user = request.args.get("user", "bob").strip() or "bob"
    rc, out, err = run_cli(user, "download", file_id)
    if rc != 0:
        flash(f"Download failed ({user}): {(err or out).strip()}", "error")
        return redirect(url_for("index"))
    downloaded = REPO_ROOT / f"client_{user}" / "downloads" / file_id
    if not downloaded.is_file():
        flash(f"Downloaded file missing at {downloaded}", "error")
        return redirect(url_for("index"))
    return send_file(
        str(downloaded),
        as_attachment=True,
        download_name=file_id,
    )


@app.route("/revoke/<file_id>", methods=["POST"])
def revoke(file_id: str):
    sender = request.form.get("sender", "alice").strip() or "alice"
    rc, out, err = run_cli(sender, "revoke", file_id)
    if rc == 0:
        flash(out.strip() or f"Revoked {file_id}", "ok")
    else:
        flash(f"Revoke failed: {(err or out).strip()}", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # 0.0.0.0 disabled on purpose — assume localhost class demo only.
    app.run(host="127.0.0.1", port=8000, debug=False)
