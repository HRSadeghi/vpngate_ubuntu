"""Certificate authentication (authtype 3) (port of CertAuth.swift).

The server sends a 20-byte random challenge and expects an RSA PKCS#1 v1.5 / SHA-1 signature
over it. The helper runs as root, so the app sends the key in ConnectConfig.privateKeyDer.
"""

from __future__ import annotations

MAX_CERT_BYTES = 16 * 1024
MAX_KEY_BYTES = 16 * 1024


class CertAuthError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def signer(private_key_der: bytes | None):
    """Returns a signer for ClientAuth.certificate. Throws (without key material) if unusable."""

    def sign(challenge: bytes) -> bytes:
        if not private_key_der:
            raise CertAuthError("Certificate authentication needs the account's private key")
        return sign_challenge(challenge, private_key_der)

    return sign


def sign_challenge(challenge: bytes, private_key_der: bytes) -> bytes:
    if len(private_key_der) > MAX_KEY_BYTES:
        raise CertAuthError("Private key too large")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    try:
        key = load_der_private_key(private_key_der, password=None)
    except Exception:
        raise CertAuthError("Private key is not a valid RSA key (PKCS#1 or PKCS#8 DER expected)") from None
    try:
        return key.sign(challenge, padding.PKCS1v15(), hashes.SHA1())
    except Exception:
        raise CertAuthError("Signing the server challenge failed") from None


def unwrap_pkcs8(der: bytes) -> bytes | None:
    """PKCS#8 PrivateKeyInfo { INTEGER 0, SEQUENCE alg, OCTET STRING key } -> the inner PKCS#1 key."""
    b = der
    pos = 0

    def read_header(pos: int, expect: int):
        if pos + 2 > len(b) or b[pos] != expect:
            return None
        ln = b[pos + 1]
        pos += 2
        if ln & 0x80:
            n = ln & 0x7F
            if n < 1 or n > 3 or pos + n > len(b):
                return None
            ln = 0
            for _ in range(n):
                ln = (ln << 8) | b[pos]
                pos += 1
        if pos + ln > len(b):
            return None
        return pos, ln

    h = read_header(pos, 0x30)
    if h is None:
        return None
    # The version INTEGER starts right after the outer SEQUENCE header.
    version = read_header(h[0], 0x02)
    if version is None or version[1] != 1 or b[version[0]] != 0:
        return None
    pos = version[0] + version[1]
    alg = read_header(pos, 0x30)
    if alg is None:
        return None
    pos = alg[0] + alg[1]
    key = read_header(pos, 0x04)
    if key is None:
        return None
    return b[key[0]:key[0] + key[1]]