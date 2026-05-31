"""Offline CA CLI per ARCHITECTURE.md §3.3.

Usage:
    python -m zerotrust.ca.ca init [--out DIR] [--password PASS]
        Generate CA keypair and self-signed cert into DIR (default: ca_data/).

    python -m zerotrust.ca.ca issue <username> [--out DIR] [--user-dir DIR]
                                   [--password PASS]
        Generate a fresh user keypair, sign it, and write
            <user-dir>/<username>/private.pem        (encrypted)
            <user-dir>/<username>/public.pem
            <user-dir>/<username>/cert.json

    python -m zerotrust.ca.ca verify <cert.json> [--ca-dir DIR]
        Verify a cert against the CA trust anchor; exits 0 on success.

Demo password handling: if --password is omitted, the value of the
``ZEROTRUST_CA_PASSWORD`` environment variable is used; if that is unset,
the CLI falls back to the documented demo password ``demo-password``. The
README MUST advertise this fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from ..common import crypto_primitives as cp
from ..common.logger import fingerprint, get_logger
from . import cert as cert_mod

DEFAULT_CA_DIR = Path("ca_data")
DEFAULT_USERS_DIR = Path("users")
DEMO_PASSWORD = b"demo-password"
DEMO_USER_PASSWORD = b"demo-password"

log = get_logger("ca")


def _resolve_password(arg_password: str | None) -> bytes:
    if arg_password is not None:
        return arg_password.encode("utf-8")
    env = os.environ.get("ZEROTRUST_CA_PASSWORD")
    if env:
        return env.encode("utf-8")
    return DEMO_PASSWORD


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Pretty for human inspection; the canonical form is computed at sign time.
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    out = Path(args.out)
    priv_path = out / "ca_private.pem"
    cert_path = out / "ca_cert.json"
    pub_path = out / "ca_public.pem"

    if priv_path.exists() or cert_path.exists():
        if not args.force:
            print(
                f"CA files already exist at {out}/. Re-run with --force to overwrite.",
                file=sys.stderr,
            )
            return 2

    password = _resolve_password(args.password)
    private_pem, public_pem = cp.generate_rsa_keypair(password)

    # Self-sign: issuer signs a cert for itself with its own brand-new key.
    self_cert = cert_mod.issue_certificate(
        subject=cert_mod.ISSUER_NAME,
        subject_pubkey_pem=public_pem,
        ca_priv_pem=private_pem,
        ca_password=password,
        validity_days=365 * 10,  # CA root: 10 years
    )

    _write_bytes(priv_path, private_pem)
    _write_bytes(pub_path, public_pem)
    _write_json(cert_path, self_cert)
    log.info("CA initialised at %s (fingerprint=%s)", out, fingerprint(public_pem))
    print(f"CA initialised at {out}/")
    print(f"  private key: {priv_path} (password-protected)")
    print(f"  public key:  {pub_path}")
    print(f"  self-signed cert: {cert_path}")
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    username = args.username
    if not username or "/" in username or username in {".", ".."}:
        print(f"refusing to issue cert for invalid username: {username!r}", file=sys.stderr)
        return 2

    ca_dir = Path(args.ca_dir)
    priv_path = ca_dir / "ca_private.pem"
    cert_path = ca_dir / "ca_cert.json"
    if not priv_path.exists() or not cert_path.exists():
        print(f"CA not initialised at {ca_dir}/. Run `init` first.", file=sys.stderr)
        return 2

    ca_password = _resolve_password(args.password)
    user_password = _resolve_password(args.user_password)

    user_dir = Path(args.user_dir) / username
    user_priv = user_dir / "private.pem"
    user_pub = user_dir / "public.pem"
    user_cert = user_dir / "cert.json"
    if user_cert.exists() and not args.force:
        print(f"User cert already exists at {user_cert}. Re-run with --force.", file=sys.stderr)
        return 2

    user_private_pem, user_public_pem = cp.generate_rsa_keypair(user_password)
    ca_private_pem = priv_path.read_bytes()

    cert = cert_mod.issue_certificate(
        subject=username,
        subject_pubkey_pem=user_public_pem,
        ca_priv_pem=ca_private_pem,
        ca_password=ca_password,
        validity_days=args.validity_days,
    )

    _write_bytes(user_priv, user_private_pem)
    _write_bytes(user_pub, user_public_pem)
    _write_json(user_cert, cert)
    log.info(
        "issued cert subject=%s serial=%s fingerprint=%s",
        username, cert["serial"], fingerprint(user_public_pem),
    )
    print(f"Issued cert for {username!r} at {user_dir}/")
    print(f"  private key: {user_priv} (password-protected)")
    print(f"  public key:  {user_pub}")
    print(f"  certificate: {user_cert}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cert_path = Path(args.cert)
    ca_pub_path = Path(args.ca_dir) / "ca_public.pem"
    if not cert_path.exists():
        print(f"cert not found: {cert_path}", file=sys.stderr)
        return 2
    if not ca_pub_path.exists():
        print(f"CA public key not found: {ca_pub_path}", file=sys.stderr)
        return 2
    cert = json.loads(cert_path.read_text(encoding="utf-8"))
    ok = cert_mod.verify_certificate(cert, ca_pub_path.read_bytes())
    if ok:
        print(f"OK: cert for subject={cert.get('subject')!r} verified.")
        return 0
    print(f"FAIL: cert for subject={cert.get('subject')!r} did NOT verify.")
    return 1


# ---------------------------------------------------------------------------
# argparse plumbing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zerotrust.ca")
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Initialise the CA keypair and self-signed cert.")
    init.add_argument("--out", default=str(DEFAULT_CA_DIR))
    init.add_argument("--password", default=None,
                      help="CA private key password (default: $ZEROTRUST_CA_PASSWORD or demo).")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    issue = sub.add_parser("issue", help="Issue a cert for <username>.")
    issue.add_argument("username")
    issue.add_argument("--ca-dir", default=str(DEFAULT_CA_DIR))
    issue.add_argument("--user-dir", default=str(DEFAULT_USERS_DIR))
    issue.add_argument("--password", default=None,
                       help="CA password (default: $ZEROTRUST_CA_PASSWORD or demo).")
    issue.add_argument("--user-password", default=None,
                       help="Password for the user's private key (default: demo).")
    issue.add_argument("--validity-days", type=int, default=cert_mod.DEFAULT_VALIDITY_DAYS)
    issue.add_argument("--force", action="store_true")
    issue.set_defaults(func=cmd_issue)

    verify = sub.add_parser("verify", help="Verify a cert against the CA trust anchor.")
    verify.add_argument("cert", help="Path to cert.json")
    verify.add_argument("--ca-dir", default=str(DEFAULT_CA_DIR))
    verify.set_defaults(func=cmd_verify)

    return p


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
