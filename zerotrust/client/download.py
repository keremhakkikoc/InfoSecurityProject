"""Client download flow — Phase 3 issues #15, #17, #18, #26.

Lists pending files for the logged-in user, downloads a chosen file,
verifies the sender's signature against their CA-signed cert, decrypts
with the unwrapped AES key, and (bonus) sends a signed ACK.
"""

from __future__ import annotations


def list_pending(session: dict) -> list[dict]:
    raise NotImplementedError("client.download.list_pending — Phase 3 issue #15")


def download_file(session: dict, file_id: str, output_dir: str) -> str:
    """Return the absolute path of the decrypted-and-verified file on disk."""
    raise NotImplementedError("client.download.download_file — Phase 3 issue #17")
