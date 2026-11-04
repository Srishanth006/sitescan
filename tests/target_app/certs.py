"""Generate throwaway certificates for the local TLS test servers."""
from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for n in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            entries.append(x509.DNSName(n))
    return x509.SubjectAlternativeName(entries)


def _write(path: Path, key, cert) -> tuple[str, str]:
    key_path = path.with_suffix(".key")
    crt_path = path.with_suffix(".crt")
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(crt_path), str(key_path)


def make_good_chain(directory: Path) -> dict[str, str]:
    """Local CA + leaf for 127.0.0.1/localhost, 2048-bit, valid one year."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("sitescan test CA"))
        .issuer_name(_name("sitescan test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(days=1))
        .not_valid_after(_now() + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("127.0.0.1"))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(days=1))
        .not_valid_after(_now() + dt.timedelta(days=365))
        .add_extension(_san(["127.0.0.1", "localhost"]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_crt, _ = _write(directory / "ca", ca_key, ca_cert)
    crt, key = _write(directory / "good", leaf_key, leaf)
    return {"ca": ca_crt, "cert": crt, "key": key}


def make_bad_cert(directory: Path) -> dict[str, str]:
    """Self-signed, 1024-bit RSA, wrong SAN, expires in 5 days."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("legacy.internal"))
        .issuer_name(_name("legacy.internal"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(days=360))
        .not_valid_after(_now() + dt.timedelta(days=5))
        .add_extension(_san(["legacy.internal"]), critical=False)
        .sign(key, hashes.SHA256())
    )
    crt, key_path = _write(directory / "bad", key, cert)
    return {"cert": crt, "key": key_path}
