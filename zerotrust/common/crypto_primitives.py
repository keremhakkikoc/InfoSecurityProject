"""Thin wrappers around the ``cryptography`` library's hazmat layer.

These functions implement the cryptographic choices frozen in
ARCHITECTURE.md §2:

* RSA-2048
* RSA-PSS (SHA-256, MGF1, salt = digest length) for signatures
* RSA-OAEP (SHA-256, MGF1) for key wrapping / session key transport
* AES-256-GCM for symmetric authenticated encryption
* HKDF-SHA256 for key derivation
* SHA-256 for hashes
* PEM private keys protected with ``BestAvailableEncryption(password)``

Frozen signatures (per ARCHITECTURE.md §10.1):

    generate_rsa_keypair() -> tuple[bytes, bytes]
    rsa_sign(private_pem, password, data) -> bytes
    rsa_verify(public_pem, data, signature) -> bool
    rsa_oaep_encrypt(public_pem, data) -> bytes
    rsa_oaep_decrypt(private_pem, password, data) -> bytes
    aes_gcm_encrypt(key, plaintext, aad) -> tuple[bytes, bytes]
    aes_gcm_decrypt(key, nonce, ciphertext, aad) -> bytes
    hkdf_derive(ikm, salt, info, length) -> bytes
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import CryptoError

# Module-wide constants — DO NOT change without updating ARCHITECTURE.md.
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_BYTES = 32      # AES-256
AES_NONCE_BYTES = 12    # GCM standard
HKDF_HASH = hashes.SHA256()
PSS_HASH = hashes.SHA256()
OAEP_HASH = hashes.SHA256()


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------

def generate_rsa_keypair(password: bytes) -> tuple[bytes, bytes]:
    """Generate a fresh RSA-2048 keypair.

    Returns ``(private_pem_encrypted, public_pem)``. The private PEM is
    protected with ``BestAvailableEncryption(password)`` per
    ARCHITECTURE.md §4.3 — passing an empty password is a programming error
    and is refused at runtime.
    """
    if not isinstance(password, (bytes, bytearray)) or len(password) == 0:
        raise ValueError("password must be non-empty bytes")
    key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(password)),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _load_private(private_pem: bytes, password: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(private_pem, password=bytes(password))
    except (ValueError, TypeError) as exc:
        # Wrong password or malformed PEM — both surface the same error.
        raise CryptoError(f"failed to load private key: {exc}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("loaded key is not an RSA private key")
    return key


def _load_public(public_pem: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"failed to load public key: {exc}") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("loaded key is not an RSA public key")
    return key


def _pss_padding() -> padding.PSS:
    # Salt length = digest length, per ARCHITECTURE.md §2.
    return padding.PSS(mgf=padding.MGF1(PSS_HASH), salt_length=PSS_HASH.digest_size)


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(OAEP_HASH), algorithm=OAEP_HASH, label=None)


def rsa_sign(private_pem: bytes, password: bytes, data: bytes) -> bytes:
    """RSA-PSS sign *data* under the given password-encrypted private key."""
    key = _load_private(private_pem, password)
    return key.sign(bytes(data), _pss_padding(), PSS_HASH)


def rsa_verify(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Return True iff *signature* is a valid PSS signature over *data*.

    Never raises on invalid signatures — returns False instead. This shape is
    convenient at call sites that use the boolean directly in fail-closed
    branches.
    """
    key = _load_public(public_pem)
    try:
        key.verify(bytes(signature), bytes(data), _pss_padding(), PSS_HASH)
        return True
    except InvalidSignature:
        return False


def rsa_oaep_encrypt(public_pem: bytes, data: bytes) -> bytes:
    """RSA-OAEP encrypt under the recipient's public key."""
    key = _load_public(public_pem)
    return key.encrypt(bytes(data), _oaep_padding())


def rsa_oaep_decrypt(private_pem: bytes, password: bytes, data: bytes) -> bytes:
    """RSA-OAEP decrypt with the password-encrypted private key.

    Raises CryptoError on any decryption failure (wrong key, padding error,
    truncation). The error message is intentionally vague — call sites should
    surface ``AUTH_FAILED`` to clients.
    """
    key = _load_private(private_pem, password)
    try:
        return key.decrypt(bytes(data), _oaep_padding())
    except ValueError as exc:
        raise CryptoError("RSA-OAEP decryption failed") from exc


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt with a fresh 12-byte nonce.

    Returns ``(nonce, ciphertext_with_tag)``. The 16-byte authentication tag
    is appended to the ciphertext by the underlying ``AESGCM`` API.
    """
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES-GCM key must be {AES_KEY_BYTES} bytes, got {len(key)}")
    nonce = os.urandom(AES_NONCE_BYTES)
    ct = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), bytes(aad))
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt; raises CryptoError on auth-tag failure."""
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES-GCM key must be {AES_KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != AES_NONCE_BYTES:
        raise ValueError(
            f"AES-GCM nonce must be {AES_NONCE_BYTES} bytes, got {len(nonce)}"
        )
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), bytes(aad))
    except InvalidTag as exc:
        # AAD mismatch, ciphertext tampering, wrong key — all surface here.
        raise CryptoError("AES-GCM authentication failed") from exc


# ---------------------------------------------------------------------------
# HKDF
# ---------------------------------------------------------------------------

def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int, extra: str = "") -> bytes:
    """HKDF-SHA256 expansion. Length must be > 0 and <= 255 * 32 bytes."""
    if length <= 0:
        raise ValueError("hkdf length must be positive")
    return HKDF(
        algorithm=HKDF_HASH,
        length=length,
        salt=bytes(salt),
        info=bytes(info),
    ).derive(bytes(ikm))
