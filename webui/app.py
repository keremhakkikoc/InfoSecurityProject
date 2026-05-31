"""Flask wrapper around the zerotrust CLI for demo / class presentation.

This is a thin UI: it does NOT reimplement the protocol. Every action
(upload, list, download, revoke, add-user) is performed by shelling out
to ``python -m zerotrust.client.cli`` or to ``make`` targets so the
real handshake, AAD-bound AES-GCM, RSA-PSS origin signature, replay
cache, and server-side chokepoint stay in the call path.

The Flask server is assumed to run on the same machine as the user's
client_<user>/ bundles and the zerotrust server (started via
``make server``). It uses the documented demo password
(``demo-password``) via ``ZEROTRUST_USER_PASSWORD`` /
``ZEROTRUST_CA_PASSWORD`` so prompts never block.

Not production: trusts localhost, no auth on the Flask side, uses a
hardcoded ``app.secret_key``. The class demo, not the protocol, is
what this file ships.
"""

from __future__ import annotations

import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

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
RESERVED_USERS = {"server"}  # not selectable as sender/recipient in the UI

# Last-N CLI invocations, rendered in the "Recent commands" panel so the demo
# can show *which* subprocess fired behind each button click.
RECENT_COMMANDS: deque[dict[str, Any]] = deque(maxlen=20)

# Maps file_id -> original filename uploaded through the UI. Lives for the
# Flask process lifetime only. The protocol intentionally does NOT carry the
# filename (untrusted server must not see it), so this is purely a local
# convenience for the demo: when Bob clicks "Download", we hand the browser
# back the .png / .pdf / whatever Alice originally chose.
UPLOAD_FILENAMES: dict[str, str] = {}

UPLOAD_OK_RE = re.compile(r"^Uploaded file_id=(\S+)", re.MULTILINE)

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")


app = Flask(__name__)
app.secret_key = "demo-secret-not-for-prod"  # noqa: S105 — demo only


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _record(cmd: list[str], rc: int, stdout: str, stderr: str) -> None:
    RECENT_COMMANDS.appendleft({
        "cmd": " ".join(shlex.quote(c) for c in cmd),
        "rc": rc,
        "ts": time.strftime("%H:%M:%S"),
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
    })


def _env_with_password() -> dict[str, str]:
    env = os.environ.copy()
    env["ZEROTRUST_USER_PASSWORD"] = DEMO_PASSWORD
    env["ZEROTRUST_CA_PASSWORD"] = DEMO_PASSWORD
    return env


def run_cli(user: str, *args: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run ``python -m zerotrust.client.cli --user <user> <args>``."""
    cmd = [sys.executable, "-m", "zerotrust.client.cli", "--user", user, *args]
    proc = subprocess.run(  # noqa: S603 — args are not shell-interpreted
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=_env_with_password(),
        timeout=timeout,
        check=False,
    )
    _record(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc.returncode, proc.stdout, proc.stderr


def run_make(*targets: str, timeout: int = 60) -> tuple[int, str, str]:
    """Run ``make <targets...>``."""
    cmd = ["make", *targets]
    proc = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=_env_with_password(),
        timeout=timeout,
        check=False,
    )
    _record(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc.returncode, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# Parsing + introspection
# ---------------------------------------------------------------------------

def parse_list_output(stdout: str) -> list[dict[str, str]]:
    """Parse CLI list output lines.

    Format: ``<file_id> sender=<u> size=<n> expires=<unix_ts>``
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


def selectable_users(state: dict) -> list[str]:
    """Users a human can act as in the UI (excludes 'server')."""
    return [u for u in state["pubkeys"] if u not in RESERVED_USERS]


def client_bundle_exists(user: str) -> bool:
    return (REPO_ROOT / f"client_{user}" / "private.pem").is_file()


def files_sent_by(state: dict, user: str) -> list[dict]:
    return [f for f in state["files"] if f["sender_id"] == user]


def inbox_for(user: str) -> tuple[list[dict[str, str]], str | None]:
    if not client_bundle_exists(user):
        return [], f"client_{user}/ bundle missing — bootstrap the user first."
    rc, out, err = run_cli(user, "list")
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
    users = selectable_users(state)

    sender = (request.args.get("sender") or (users[0] if users else "")).strip()
    inbox_user = (request.args.get("inbox") or (users[1] if len(users) > 1 else (users[0] if users else ""))).strip()

    pending: list[dict[str, str]] = []
    list_err: str | None = None
    if inbox_user:
        pending, list_err = inbox_for(inbox_user)

    sent = files_sent_by(state, sender) if sender else []

    return render_template(
        "index.html",
        state=state,
        users=users,
        sender=sender,
        inbox_user=inbox_user,
        sent=sent,
        pending=pending,
        list_err=list_err,
        recent=list(RECENT_COMMANDS),
    )


@app.route("/upload", methods=["POST"])
def upload():
    sender = request.form.get("sender", "").strip()
    recipient = request.form.get("recipient", "").strip()
    fp = request.files.get("file")

    if not sender or not recipient:
        flash("Sender and recipient are required.", "error")
        return redirect(url_for("index", sender=sender or None))
    if fp is None or not fp.filename:
        flash("No file selected.", "error")
        return redirect(url_for("index", sender=sender))

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(fp.filename).name
    save_path = UPLOADS_DIR / safe_name
    fp.save(str(save_path))

    rc, out, err = run_cli(sender, "upload", recipient, str(save_path))
    if rc == 0:
        flash(out.strip(), "ok")
        # Remember the original filename so /download can hand the
        # browser back the right extension instead of the bare UUID.
        m = UPLOAD_OK_RE.search(out)
        if m:
            UPLOAD_FILENAMES[m.group(1)] = safe_name
    else:
        flash(f"Upload failed: {(err or out).strip()}", "error")
    return redirect(url_for("index", sender=sender, inbox=recipient))


@app.route("/download/<file_id>")
def download(file_id: str):
    user = (request.args.get("user") or "").strip()
    if not user:
        flash("download needs ?user=<name>", "error")
        return redirect(url_for("index"))
    rc, out, err = run_cli(user, "download", file_id)
    if rc != 0:
        flash(f"Download failed ({user}): {(err or out).strip()}", "error")
        return redirect(url_for("index", inbox=user))
    downloaded = REPO_ROOT / f"client_{user}" / "downloads" / file_id
    if not downloaded.is_file():
        flash(f"Downloaded file missing at {downloaded}", "error")
        return redirect(url_for("index", inbox=user))
    # Hand the browser the original filename if we know it (uploads done
    # through this Flask process during its current lifetime). Falls back
    # to the file_id so CLI-side uploads still produce a usable name.
    nice_name = UPLOAD_FILENAMES.get(file_id, file_id)
    return send_file(
        str(downloaded),
        as_attachment=True,
        download_name=nice_name,
    )


@app.route("/revoke/<file_id>", methods=["POST"])
def revoke(file_id: str):
    sender = request.form.get("sender", "").strip()
    if not sender:
        flash("revoke needs sender", "error")
        return redirect(url_for("index"))
    rc, out, err = run_cli(sender, "revoke", file_id)
    if rc == 0:
        flash(out.strip() or f"Revoked {file_id}", "ok")
    else:
        flash(f"Revoke failed: {(err or out).strip()}", "error")
    return redirect(url_for("index", sender=sender))


@app.route("/users", methods=["POST"])
def add_user():
    name = request.form.get("username", "").strip().lower()
    if not USERNAME_RE.match(name):
        flash(
            "Username must start with a-z and contain only a-z, 0-9, '_' or '-' "
            "(max 31 chars).",
            "error",
        )
        return redirect(url_for("index"))
    if name in RESERVED_USERS:
        flash(f"'{name}' is reserved.", "error")
        return redirect(url_for("index"))

    rc, out, err = run_make(f"user", f"USER={name}", timeout=120)
    if rc == 0:
        flash(f"Bootstrapped user '{name}' (cert + client bundle + server registration).", "ok")
    else:
        flash(
            f"User bootstrap failed: {(err or out).strip().splitlines()[-1] if (err or out).strip() else f'exit {rc}'}",
            "error",
        )
    return redirect(url_for("index", sender=name))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
