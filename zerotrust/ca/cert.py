"""Custom-JSON certificate issue / verify per ARCHITECTURE.md §3.

A certificate is the canonical JSON object documented in §3.2:

    {
      "subject": "alice",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n",
      "issuer": "CA",
      "valid_from": <unix>,
      "valid_until": <unix>,
      "serial": "<uuid4>",
      "signature": "<base64 RSA-PSS signature>"
    }

The signature covers ``canonical_json(cert_without_signature)``. Any
deviation from canonical form breaks verification — NEVER compare on
re-serialised non-canonical JSON.

Frozen signatures (per ARCHITECTURE.md §10.1):

    issue_certificate(subject, subject_pubkey_pem, ca_priv_pem, ca_password,
                      validity_days=365) -> dict
    verify_certificate(cert, ca_pubkey_pem, expected_subject=None) -> bool
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Any

from ..common import crypto_primitives as cp
from ..common.canonical import canonical_json

ISSUER_NAME = "ZeroTrustCA"
DEFAULT_VALIDITY_DAYS = 365


def _strip_signature(cert: dict) -> dict:
    """Return a copy of *cert* with the ``signature`` field removed."""
    return {k: v for k, v in cert.items() if k != "signature"}


def issue_certificate(
    subject: str,
    subject_pubkey_pem: bytes,
    ca_priv_pem: bytes,
    ca_password: bytes,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> dict:
    """Issue and sign a certificate binding *subject* to *subject_pubkey_pem*.

    Returns the full certificate dict including the base64-encoded RSA-PSS
    signature. The CA's own self-signed cert is created by issuing a
    certificate to the issuer name with the CA's own public key.
    """
    if not isinstance(subject, str) or not subject:
        raise ValueError("subject must be a non-empty string")
    if validity_days <= 0:
        raise ValueError("validity_days must be positive")

    now = int(time.time())
    cert: dict[str, Any] = {
        "subject": subject,
        "public_key_pem": subject_pubkey_pem.decode("ascii"),
        "issuer": ISSUER_NAME,
        "valid_from": now,
        "valid_until": now + validity_days * 86400,
        "serial": str(uuid.uuid4()),
    }
    sig = cp.rsa_sign(ca_priv_pem, ca_password, canonical_json(cert))
    cert["signature"] = base64.b64encode(sig).decode("ascii")
    return cert


def verify_certificate(
    cert: dict,
    ca_pubkey_pem: bytes,
    expected_subject: str | None = None,
) -> bool:
    """Return True iff signature is valid, cert is currently in date, AND
    (if ``expected_subject`` is supplied) the cert's subject matches.

    All three checks from ARCHITECTURE.md §3.4 are enforced here:
      1. ``valid_until > now >= valid_from``
      2. RSA-PSS signature verifies against ``ca_pubkey_pem``
      3. (optional) ``cert["subject"] == expected_subject``

    Returns False — never raises — on any malformed cert or check failure.

    The subject comparison uses plain ``==`` deliberately: subjects are
    public identifiers, not secrets, so there is no timing side-channel
    concern.
    """
    if not isinstance(cert, dict):
        return False
    required = {"subject", "public_key_pem", "issuer", "valid_from",
                "valid_until", "serial", "signature"}
    if required - cert.keys():
        return False
    try:
        sig = base64.b64decode(cert["signature"], validate=True)
    except Exception:  # noqa: BLE001
        return False
    body = canonical_json(_strip_signature(cert))
    if not cp.rsa_verify(ca_pubkey_pem, body, sig):
        return False

    now = int(time.time())
    if not (cert["valid_from"] <= now <= cert["valid_until"]):
        return False

    if expected_subject is not None and cert["subject"] != expected_subject:
        return False

    return True
