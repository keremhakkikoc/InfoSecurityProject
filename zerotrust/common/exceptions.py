"""Custom exception hierarchy per AI.md §4.

Defining specific exception types makes the fail-closed flow explicit and testable.
"""


class ZeroTrustError(Exception):
    """Base for all project errors."""


class CryptoError(ZeroTrustError):
    """Raised on any cryptographic failure (auth tag, signature, decryption)."""


class AuthError(ZeroTrustError):
    """Raised on authentication / authorization failures."""


class ProtocolError(ZeroTrustError):
    """Raised on malformed or unexpected protocol messages."""
