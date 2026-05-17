"""Client CLI entry point.

Usage::

    python -m zerotrust.client.cli --user alice login
    python -m zerotrust.client.cli --user alice upload <recipient> <file>   # M2 #12
    python -m zerotrust.client.cli --user alice list                        # M3 #15
    python -m zerotrust.client.cli --user alice download <file_id>          # M3 #17

This module implements the ``login`` subcommand (issue #15) and registers
placeholder argparse subcommands for the upload/list/download verbs so
future milestones can fill them in without changing the dispatcher shape.

Password handling (AI.md §3.10):
    priority: ``--password`` arg > env var ``ZEROTRUST_USER_PASSWORD`` >
    interactive ``getpass.getpass()`` prompt. The password is held in
    memory for the lifetime of the command only.

Error reporting (AI.md §4.36):
    Auth / crypto / protocol failures collapse to the single string
    ``AUTH_FAILED`` on stderr with no stack trace. Local filesystem and
    network errors expose their underlying cause because they are not
    secrets.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Iterable

from ..common.exceptions import AuthError, CryptoError, ProtocolError, ZeroTrustError
from .session import ClientAssetError, connected_session, login_session
from .upload import upload_file

AUTH_FAILED = "AUTH_FAILED"


def _resolve_password(arg_password: str | None) -> bytes:
    """Resolve the user's private-key password.

    Priority: ``--password`` > ``ZEROTRUST_USER_PASSWORD`` > interactive
    prompt. Mirrors the CA CLI's pattern.
    """
    if arg_password is not None:
        return arg_password.encode("utf-8")
    env_password = os.environ.get("ZEROTRUST_USER_PASSWORD")
    if env_password:
        return env_password.encode("utf-8")
    return getpass.getpass("User private key password: ").encode("utf-8")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_login(args: argparse.Namespace) -> int:
    """Open the session and print the documented success banner."""
    password = _resolve_password(args.password)
    try:
        state = login_session(args.user, password)
    except ClientAssetError as exc:
        # Local filesystem errors — safe to surface verbatim.
        print(str(exc), file=sys.stderr)
        return 1
    except (ConnectionRefusedError, TimeoutError) as exc:
        # Network errors — acceptable to expose, not a security leak.
        print(str(exc).lower(), file=sys.stderr)
        return 1
    except OSError as exc:
        print(str(exc).lower(), file=sys.stderr)
        return 1
    except (AuthError, CryptoError, ProtocolError, ZeroTrustError):
        # All auth-class failures collapse to the generic banner.
        print(AUTH_FAILED, file=sys.stderr)
        return 1

    print(
        f"Authenticated as {args.user}; "
        f"session established with {state['peer_subject']}."
    )
    return 0


def _not_implemented(command: str) -> int:
    print(f"{command} command is not implemented yet.", file=sys.stderr)
    return 2


def cmd_upload(args: argparse.Namespace) -> int:
    """Open a session and upload ``args.file`` to ``args.recipient``."""
    password = _resolve_password(args.password)
    expiration_seconds = args.expires_days * 86400
    try:
        with connected_session(args.user, password) as session:
            ack = upload_file(
                session,
                args.recipient,
                args.file,
                expiration_seconds=expiration_seconds,
            )
    except FileNotFoundError:
        # Local file doesn't exist — issue spec says exit 1, no network hit.
        print("FILE_NOT_FOUND", file=sys.stderr)
        return 1
    except ClientAssetError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ConnectionRefusedError, TimeoutError) as exc:
        print(str(exc).lower(), file=sys.stderr)
        return 1
    except OSError as exc:
        print(str(exc).lower(), file=sys.stderr)
        return 1
    except ProtocolError as exc:
        # Server-side ERROR codes (NOT_FOUND, AUTH_FAILED, STALE, REPLAY,
        # MALFORMED, ...) and oversize local checks all surface here.
        print(str(exc), file=sys.stderr)
        return 1
    except (AuthError, CryptoError, ZeroTrustError):
        print(AUTH_FAILED, file=sys.stderr)
        return 1

    print(
        f"Uploaded file_id={ack['file_id']} to {args.recipient}; "
        f"expires={ack['expiration']}"
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:  # pragma: no cover - placeholder
    return _not_implemented("list")


def cmd_download(args: argparse.Namespace) -> int:  # pragma: no cover - placeholder
    return _not_implemented("download")


# ---------------------------------------------------------------------------
# argparse plumbing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zerotrust.client.cli")
    parser.add_argument(
        "--user",
        required=True,
        help="Username controlling which client_<user>/ directory to load.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help=(
            "Private-key password. Default: $ZEROTRUST_USER_PASSWORD or "
            "interactive prompt. NEVER cached to disk."
        ),
    )

    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="Authenticate and establish a session.")
    login.set_defaults(func=cmd_login)

    upload = sub.add_parser("upload", help="Upload a file to a recipient (M2 #12).")
    upload.add_argument("recipient", help="Recipient username.")
    upload.add_argument("file", help="Path to the local file to upload.")
    upload.add_argument(
        "--expires-days",
        type=int,
        default=7,
        help="How many days the upload is valid for (default: 7).",
    )
    upload.set_defaults(func=cmd_upload)

    listing = sub.add_parser("list", help="List inbox files (M3 #15).")
    listing.set_defaults(func=cmd_list)

    download = sub.add_parser("download", help="Download a file by file_id (M3 #17).")
    download.add_argument("file_id", help="Identifier of the file to download.")
    download.set_defaults(func=cmd_download)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
