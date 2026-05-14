"""Tests for the CA module: cert issuing, verification, and CLI flow."""

from __future__ import annotations

import json
import time

import pytest

from zerotrust.ca import ca as ca_cli
from zerotrust.ca import cert as cert_mod
from zerotrust.common import crypto_primitives as cp


PASSWORD = b"ca-test-password"


@pytest.fixture
def ca_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture
def user_keys():
    return cp.generate_rsa_keypair(PASSWORD)


# ---------------------------------------------------------------------------
# Library-level: issue / verify
# ---------------------------------------------------------------------------

def test_issued_cert_verifies(ca_keys, user_keys):
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub) is True
    assert cert["subject"] == "alice"
    assert "signature" in cert


def test_verify_rejects_tampered_subject(ca_keys, user_keys):
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    cert["subject"] = "mallory"
    assert cert_mod.verify_certificate(cert, ca_pub) is False


# ---------------------------------------------------------------------------
# Subject pinning (#6) — third check from ARCHITECTURE.md §3.4
# ---------------------------------------------------------------------------

def test_verify_with_matching_expected_subject(ca_keys, user_keys):
    """When expected_subject matches the cert's subject, verification passes."""
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub, expected_subject="alice") is True


def test_verify_with_mismatched_expected_subject(ca_keys, user_keys):
    """An otherwise-valid cert is rejected if the subject does not match.

    This is the defence against identity-substitution: an attacker who replays
    Alice's cert during a handshake where the server expected Bob must be
    rejected before any session key is established.
    """
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub, expected_subject="mallory") is False


def test_verify_default_subject_arg_keeps_old_behaviour(ca_keys, user_keys):
    """Calling without expected_subject behaves exactly like before #6."""
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    # Two-arg form == three-arg form with expected_subject=None.
    assert cert_mod.verify_certificate(cert, ca_pub) is True
    assert cert_mod.verify_certificate(cert, ca_pub, expected_subject=None) is True


def test_verify_rejects_tampered_pubkey(ca_keys, user_keys):
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    _, attacker_pub = cp.generate_rsa_keypair(PASSWORD)
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    cert["public_key_pem"] = attacker_pub.decode("ascii")
    assert cert_mod.verify_certificate(cert, ca_pub) is False


def test_verify_rejects_signed_by_wrong_ca(ca_keys, user_keys):
    ca_priv, _ = ca_keys
    _, user_pub = user_keys
    _, other_ca_pub = cp.generate_rsa_keypair(PASSWORD)
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    assert cert_mod.verify_certificate(cert, other_ca_pub) is False


def test_verify_rejects_expired_cert(ca_keys, user_keys, monkeypatch):
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD,
                                       validity_days=1)
    # Move clock forward 2 days.
    real_time = time.time()
    monkeypatch.setattr("zerotrust.ca.cert.time.time", lambda: real_time + 2 * 86400)
    assert cert_mod.verify_certificate(cert, ca_pub) is False


def test_verify_rejects_not_yet_valid_cert(ca_keys, user_keys, monkeypatch):
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    # Pretend we are 1 day before issuance.
    real_time = time.time()
    monkeypatch.setattr("zerotrust.ca.cert.time.time", lambda: real_time - 2 * 86400)
    assert cert_mod.verify_certificate(cert, ca_pub) is False


def test_verify_rejects_missing_fields(ca_keys, user_keys):
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    del cert["serial"]
    assert cert_mod.verify_certificate(cert, ca_pub) is False


def test_canonical_signing_resists_key_reordering(ca_keys, user_keys):
    """Re-serialising the cert with a different key order must still verify.

    This guards against a regression where someone serialises with
    ``sort_keys=False`` before signing. Canonical JSON in cert.py keeps
    verification robust against incidental re-ordering.
    """
    ca_priv, ca_pub = ca_keys
    _, user_pub = user_keys
    cert = cert_mod.issue_certificate("alice", user_pub, ca_priv, PASSWORD)
    # Round-trip through json with explicit ordering changes:
    reordered = json.loads(json.dumps(dict(reversed(list(cert.items())))))
    assert cert_mod.verify_certificate(reordered, ca_pub) is True


# ---------------------------------------------------------------------------
# CLI integration: init -> issue -> verify
# ---------------------------------------------------------------------------

def test_cli_init_issue_verify_flow(tmp_path, capsys):
    ca_dir = tmp_path / "ca"
    users_dir = tmp_path / "users"
    pwd = "cli-test-password"

    rc = ca_cli.main(["init", "--out", str(ca_dir), "--password", pwd])
    assert rc == 0
    assert (ca_dir / "ca_private.pem").exists()
    assert (ca_dir / "ca_public.pem").exists()
    assert (ca_dir / "ca_cert.json").exists()

    rc = ca_cli.main([
        "issue", "alice",
        "--ca-dir", str(ca_dir),
        "--user-dir", str(users_dir),
        "--password", pwd,
        "--user-password", pwd,
    ])
    assert rc == 0
    assert (users_dir / "alice" / "private.pem").exists()
    assert (users_dir / "alice" / "cert.json").exists()

    rc = ca_cli.main(["verify",
                      str(users_dir / "alice" / "cert.json"),
                      "--ca-dir", str(ca_dir)])
    assert rc == 0


def test_cli_init_refuses_overwrite_without_force(tmp_path, capsys):
    ca_dir = tmp_path / "ca"
    pwd = "cli-test-password"
    assert ca_cli.main(["init", "--out", str(ca_dir), "--password", pwd]) == 0
    assert ca_cli.main(["init", "--out", str(ca_dir), "--password", pwd]) == 2


def test_cli_issue_rejects_unknown_ca_dir(tmp_path):
    rc = ca_cli.main([
        "issue", "alice",
        "--ca-dir", str(tmp_path / "nope"),
        "--user-dir", str(tmp_path / "users"),
        "--password", "x", "--user-password", "x",
    ])
    assert rc == 2


def test_cli_issue_rejects_path_traversal_username(tmp_path):
    ca_dir = tmp_path / "ca"
    ca_cli.main(["init", "--out", str(ca_dir), "--password", "x"])
    rc = ca_cli.main([
        "issue", "../../etc/passwd",
        "--ca-dir", str(ca_dir),
        "--user-dir", str(tmp_path / "users"),
        "--password", "x", "--user-password", "x",
    ])
    assert rc == 2
