"""Turns user-supplied certificate/key files into the DER blobs the helper needs
(port of CertImport.swift, via the cryptography package).

Only RSA is supported (SoftEther signs the server challenge with RSA PKCS#1 v1.5 / SHA-1).
Nothing here touches the keyring or disk.
"""

from __future__ import annotations

import base64
import binascii


class CertImportError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _fail(message: str) -> CertImportError:
    return CertImportError(message)


def pem_blocks(data: bytes) -> list[tuple[str, list[str], bytes]]:
    """(label, headers, der) for each BEGIN/END block."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    out = []
    label = None
    headers: list[str] = []
    body = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("-----BEGIN ") and line.endswith("-----"):
            label = line[len("-----BEGIN "):-len("-----")]
            headers = []
            body = ""
        elif line.startswith("-----END "):
            if label is not None:
                try:
                    der = base64.b64decode(body)
                    out.append((label, headers, der))
                except (binascii.Error, ValueError):
                    pass
            label = None
        elif label is not None:
            if ":" in line:
                headers.append(line)
            else:
                body += line
    return out


def parse_certificate(data: bytes) -> bytes:
    """Accepts a PEM or DER X.509 certificate; returns the DER."""
    from cryptography import x509
    for label, _headers, der in pem_blocks(data):
        if label in ("CERTIFICATE", "X509 CERTIFICATE"):
            try:
                x509.load_der_x509_certificate(der)
                return der
            except Exception:
                continue
    if data[:1] == b"\x30":
        try:
            x509.load_der_x509_certificate(data)
            return data
        except Exception:
            pass
    raise _fail("That file is not an X.509 certificate (PEM or DER expected).")


def parse_private_key(data: bytes) -> bytes:
    """Accepts PKCS#1 (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) or raw DER of either;
    always returns PKCS#1 DER."""
    from cryptography.hazmat.primitives.serialization import (load_der_private_key,
                                                              load_pem_private_key)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    der = None
    for label, headers, block in pem_blocks(data):
        low_headers = " ".join(headers).lower()
        if label == "ENCRYPTED PRIVATE KEY":
            raise _fail("The private key is passphrase-protected. Remove the passphrase first "
                        "(openssl rsa -in key.pem -out plain.pem) or import a .p12 file instead.")
        if label == "EC PRIVATE KEY":
            raise _fail("Only RSA keys are supported for certificate login (this key is EC).")
        if label == "DSA PRIVATE KEY":
            raise _fail("Only RSA keys are supported for certificate login (this key is DSA).")
        if label == "RSA PRIVATE KEY":
            if "encrypted" in low_headers:
                raise _fail("The private key is passphrase-protected. Remove the passphrase first "
                            "(openssl rsa -in key.pem -out plain.pem) or import a .p12 file instead.")
            der = block
        elif label == "PRIVATE KEY":
            der = block
        if der is not None:
            break
    if der is None and not pem_blocks(data) and data[:1] == b"\x30":
        der = data
    if der is None:
        raise _fail("That file is not an RSA private key (PEM or DER expected).")
    try:
        key = load_der_private_key(der, password=None)
    except Exception:
        try:
            key = load_pem_private_key(der, password=None)
        except Exception:
            raise _fail("That file is not an RSA private key (PEM or DER expected).") from None
        # A PEM block reached here as DER bytes; loading directly failed, so re-encode.
    if not isinstance(key, RSAPrivateKey):
        raise _fail("Only RSA keys are supported for certificate login (this key is not RSA).")
    pkcs1 = key.private_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.DER,
        format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption())
    return pkcs1


def identity(certificate_file: bytes, key_file: bytes) -> tuple[bytes, bytes]:
    """(certDer, privateKeyDer) from two files; checks they belong together."""
    cert = parse_certificate(certificate_file)
    key = parse_private_key(key_file)
    require_match(cert_der=cert, key_der=key)
    return cert, key


def require_match(cert_der: bytes, key_der: bytes) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        cert_key = cert.public_key()
        priv = load_der_private_key(key_der, password=None)
        priv_pub = priv.public_key()
    except Exception:
        raise _fail("The private key does not belong to the certificate.") from None
    if _public_der(cert_key) != _public_der(priv_pub):
        raise _fail("The private key does not belong to the certificate.")


def _public_der(key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def import_pkcs12(data: bytes, passphrase: str) -> tuple[bytes, bytes]:
    """(certDer, privateKeyDer) from a .p12/.pfx file."""
    from cryptography.hazmat.primitives.serialization import pkcs12
    try:
        key, cert, _extra = pkcs12.load_key_and_certificates(
            data, passphrase.encode("utf-8") if passphrase else None)
    except Exception:
        raise _fail("Wrong passphrase for the .p12 file.") from None
    if key is None or cert is None:
        raise _fail("Could not read the .p12 file: the file contains no certificate with a private key")
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    if not isinstance(key, RSAPrivateKey):
        raise _fail("Only RSA keys are supported for certificate login (this key is not RSA).")
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    key_der = key.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    cert_der = cert.public_bytes(Encoding.DER)
    try:
        require_match(cert_der=cert_der, key_der=key_der)
    except CertImportError:
        raise
    return cert_der, key_der