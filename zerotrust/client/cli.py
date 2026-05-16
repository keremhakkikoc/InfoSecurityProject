"""Client CLI entry point — Phase 2 issue #9; Phase 3 issues #15, #17.

Exposes:
    python -m zerotrust.client.cli --user <name> login
    python -m zerotrust.client.cli --user <name> upload <recipient> <file>
    python -m zerotrust.client.cli --user <name> list
    python -m zerotrust.client.cli --user <name> download <file_id>
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from ..common.exceptions import AuthError, CryptoError, ProtocolError, ZeroTrustError
from .session import ClientAssetError, connected_session, login_session
from .upload import upload_file

AUTH_FAILED = "AUTH_FAILED"


def _resolve_password(arg_password: str | None) -> bytes:
    if arg_password is not None:
        return arg_password.encode("utf-8")
    env_password = os.environ.get("ZEROTRUST_USER_PASSWORD")
    if env_password:
        return env_password.encode("utf-8")
    return getpass.getpass("User private key password: ").encode("utf-8")


def cmd_login(args: argparse.Namespace) -> int:
    password = _resolve_password(args.password)
    try:
        state = login_session(args.user, password)
    except ClientAssetError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ConnectionRefusedError, TimeoutError) as exc:
        print(str(exc).lower(), file=sys.stderr)
        return 1
    except OSError as exc:
        print(str(exc).lower(), file=sys.stderr)
        return 1
    except (AuthError, CryptoError, ProtocolError, ZeroTrustError):
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
    path = Path(args.file)
    if not path.is_file():
        print("FILE_NOT_FOUND", file=sys.stderr)
        return 1

    password = _resolve_password(args.password)
    try:
        with connected_session(args.user, password) as session:
            ack = upload_file(
                session,
                args.recipient,
                args.file,
                expiration_seconds=args.expires_days * 86400,
            )
    except FileNotFoundError:
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


def cmd_list(args: argparse.Namespace) -> int:
    return _not_implemented("list")


def cmd_download(args: argparse.Namespace) -> int:
    return _not_implemented("download")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zerotrust.client")
    parser.add_argument("--user", required=True, help="Client username, e.g. alice.")
    parser.add_argument(
        "--password",
        default=None,
        help="Private-key password (default: $ZEROTRUST_USER_PASSWORD or prompt).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="Connect to the server and authenticate.")
    login.set_defaults(func=cmd_login)

    upload = sub.add_parser("upload", help="Upload a file for another user.")
    upload.add_argument("recipient")
    upload.add_argument("file")
    upload.add_argument(
        "--expires-days",
        type=int,
        default=7,
        help="Expiration window in days (default: 7).",
    )
    upload.set_defaults(func=cmd_upload)

    list_cmd = sub.add_parser("list", help="List pending files.")
    list_cmd.set_defaults(func=cmd_list)

    download = sub.add_parser("download", help="Download a pending file.")
    download.add_argument("file_id")
    download.set_defaults(func=cmd_download)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
