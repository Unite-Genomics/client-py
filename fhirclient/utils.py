import base64
import hashlib
import os
from typing import Dict


def base64url_encode(data: bytes) -> str:
    """Encodes bytes using base64url format (RFC 4648) without padding for URL-safe string representation.

    Used in OAuth/PKCE flows where padding characters are not allowed in URLs.
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def digest_sha256(payload: str) -> bytes:
    """Returns SHA-256 digest of a UTF-8 string."""
    sha256 = hashlib.sha256()
    sha256.update(payload.encode('utf-8'))
    return sha256.digest()


def generate_pkce_challenge(entropy: int = 256) -> Dict[str, str]:
    """Generates a PKCE code verifier and challenge for OAuth 2.0 PKCE extension.

    The entropy parameter controls the randomness of the code verifier (default: 96 bits).
    Returns a dict with 'code_verifier' and 'code_challenge' using S256 method.
    """

    if entropy < 256:
        raise ValueError('Entropy must be at least 256 bits for secure PKCE verification')

    input_bytes = os.urandom(entropy // 8)
    code_verifier = base64url_encode(input_bytes)
    code_challenge = base64url_encode(digest_sha256(code_verifier))
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge
    }
