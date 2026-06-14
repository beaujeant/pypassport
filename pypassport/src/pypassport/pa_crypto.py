"""Pure-Python cryptography for the passport verification / read path.

This module replaces the previous ``openssl`` command-line subprocess calls used
by Passive Authentication, Active Authentication and the fingerprint report. It
works entirely in-process on ``bytes`` using the project's existing dependencies
(``pyasn1`` / ``pyasn1-modules`` for ASN.1, ``pycryptodome`` for RSA and
``ecdsa`` for elliptic-curve signatures). No temporary files, no shell, and no
dependency on a system ``openssl`` binary.
"""

import base64
import datetime
import hashlib
import os

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules import rfc5280, rfc5652

from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

import ecdsa
from ecdsa.util import sigdecode_der

from pypassport.der_object_identifier import OID as _OID_NAMES


class PaCryptoError(Exception):
    pass


class ChainVerificationError(PaCryptoError):
    pass


# signatureAlgorithm OID -> pycryptodome hash module (RSA PKCS#1 v1.5)
_RSA_SIG_OID = {
    "1.2.840.113549.1.1.5":  SHA1,    # sha1WithRSAEncryption
    "1.2.840.113549.1.1.14": SHA224,  # sha224WithRSAEncryption
    "1.2.840.113549.1.1.11": SHA256,  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": SHA384,  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": SHA512,  # sha512WithRSAEncryption
}

# signatureAlgorithm OID -> hashlib constructor (ECDSA, X9.62 / RFC 5758)
_ECDSA_SIG_OID = {
    "1.2.840.10045.4.1":   hashlib.sha1,    # ecdsa-with-SHA1
    "1.2.840.10045.4.3.1": hashlib.sha224,  # ecdsa-with-SHA224
    "1.2.840.10045.4.3.2": hashlib.sha256,  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": hashlib.sha384,  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": hashlib.sha512,  # ecdsa-with-SHA512
}


# --------------------------------------------------------------------------- #
# PEM / DER helpers
# --------------------------------------------------------------------------- #

def _pem_or_der_to_der(raw):
    """Return the DER bytes of a certificate given either DER or PEM input."""
    if raw.lstrip().startswith(b"-----BEGIN"):
        body = b"".join(line for line in raw.splitlines() if b"-----" not in line)
        return base64.b64decode(body)
    return raw


def dsc_der_to_pem(der):
    """Wrap a DER certificate in a PEM ``CERTIFICATE`` envelope (bytes)."""
    b64 = base64.encodebytes(der).decode("ascii")
    return ("-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n").encode("ascii")


# --------------------------------------------------------------------------- #
# CMS / PKCS#7 SignedData (EF.SOD)
# --------------------------------------------------------------------------- #

def _decode_signed_data(sod_body):
    """Decode an EF.SOD body (DER ContentInfo) into its SignedData structure."""
    content_info, _ = der_decode(sod_body, asn1Spec=rfc5652.ContentInfo())
    signed_data, _ = der_decode(content_info["content"], asn1Spec=rfc5652.SignedData())
    return signed_data


def extract_eContent(sod_body):
    """Return the encapsulated content of EF.SOD (the LDSSecurityObject DER).

    Equivalent to ``openssl smime -verify -noverify``: returns the octets that
    are signed, i.e. the inner LDSSecurityObject ready for ASN.1 decoding.
    """
    signed_data = _decode_signed_data(sod_body)
    eContent = signed_data["encapContentInfo"]["eContent"]
    if not eContent.hasValue():
        raise PaCryptoError("EF.SOD has no encapsulated content")
    return bytes(eContent)


def extract_dsc_der(sod_body):
    """Return the Document Signer certificate (DER) embedded in EF.SOD, or None."""
    signed_data = _decode_signed_data(sod_body)
    certs = signed_data["certificates"]
    if not certs.hasValue():
        return None
    for choice in certs:
        if choice.getName() == "certificate":
            return der_encode(choice["certificate"])
    return None


# --------------------------------------------------------------------------- #
# X.509 chain verification (replaces ``openssl verify -CApath``)
# --------------------------------------------------------------------------- #

def _to_utc(dt):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _cert_time(time_choice):
    """Convert an rfc5280 ``Time`` (utcTime or generalTime) to a UTC datetime."""
    return _to_utc(time_choice.getComponent().asDateTime)


def _check_validity(cert, now):
    validity = cert["tbsCertificate"]["validity"]
    not_before = _cert_time(validity["notBefore"])
    not_after = _cert_time(validity["notAfter"])
    if not (not_before <= now <= not_after):
        raise ChainVerificationError("certificate is outside its validity period")


def _verify_signature(subject_cert, issuer_cert):
    """Verify that ``subject_cert`` is signed by ``issuer_cert``'s public key."""
    tbs_der = der_encode(subject_cert["tbsCertificate"])
    sig_oid = str(subject_cert["signatureAlgorithm"]["algorithm"])
    sig_bytes = subject_cert["signature"].asOctets()
    spki_der = der_encode(issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if sig_oid in _RSA_SIG_OID:
        digest = _RSA_SIG_OID[sig_oid].new(tbs_der)
        pkcs1_15.new(RSA.import_key(spki_der)).verify(digest, sig_bytes)
        return

    if sig_oid in _ECDSA_SIG_OID:
        vk = ecdsa.VerifyingKey.from_der(spki_der)
        vk.verify(sig_bytes, tbs_der,
                  hashfunc=_ECDSA_SIG_OID[sig_oid], sigdecode=sigdecode_der)
        return

    raise ChainVerificationError("unsupported signature algorithm OID " + sig_oid)


def _load_csca_certs(csca_dir):
    """Yield (subject_der, Certificate) for every parsable certificate in the dir."""
    for filename in sorted(os.listdir(csca_dir)):
        if filename.endswith(".0"):
            # Legacy OpenSSL c_rehash symlink/copies are redundant now.
            continue
        path = os.path.join(csca_dir, filename)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as handle:
                der = _pem_or_der_to_der(handle.read())
            cert, _ = der_decode(der, asn1Spec=rfc5280.Certificate())
        except Exception:
            continue
        yield der_encode(cert["tbsCertificate"]["subject"]), cert


def verify_certificate_chain(dsc_der, csca_dir, at_time=None):
    """Verify a Document Signer certificate against the trusted CSCA directory.

    The DSC issuer Distinguished Name is matched (by DER-encoded ``Name``) against
    the subject of each CSCA in ``csca_dir``; the DSC signature and validity period
    are then checked. Supports both RSA and ECDSA signatures.

    @return: True on success.
    @raise ChainVerificationError: if no issuer is found or verification fails.
    """
    now = at_time or datetime.datetime.now(datetime.timezone.utc)
    dsc, _ = der_decode(dsc_der, asn1Spec=rfc5280.Certificate())
    issuer_der = der_encode(dsc["tbsCertificate"]["issuer"])

    candidates = [cert for subject_der, cert in _load_csca_certs(csca_dir)
                  if subject_der == issuer_der]
    if not candidates:
        raise ChainVerificationError("no CSCA matching the DSC issuer was found")

    last_error = None
    for csca in candidates:
        try:
            _check_validity(dsc, now)
            _verify_signature(dsc, csca)
            return True
        except Exception as error:
            last_error = error
    raise ChainVerificationError("DSC verification failed: " + str(last_error))


# --------------------------------------------------------------------------- #
# RSA helpers (Active Authentication)
# --------------------------------------------------------------------------- #

def raw_rsa(spki_der, signature):
    """Raw RSA public-key transform (``s ** e mod n``), no padding.

    Equivalent to ``openssl rsautl -raw -verify``: returns the full
    modulus-length block, including the leading ``0x6A`` and trailing ``0xBC``
    bytes that Active Authentication inspects.
    """
    key = RSA.import_key(spki_der)
    k = (key.n.bit_length() + 7) // 8
    m = pow(int.from_bytes(signature, "big"), key.e, key.n)
    return m.to_bytes(k, "big")


def rsa_pubkey_to_pem(spki_der):
    """Return the PEM ``PUBLIC KEY`` encoding (bytes) of a DER SubjectPublicKeyInfo."""
    return RSA.import_key(spki_der).export_key(format="PEM")


# --------------------------------------------------------------------------- #
# Certificate display helpers (fingerprint report)
# --------------------------------------------------------------------------- #

def cert_serial(dsc_der):
    """Return the certificate serial number, mirroring ``openssl x509 -serial``."""
    cert, _ = der_decode(dsc_der, asn1Spec=rfc5280.Certificate())
    serial = int(cert["tbsCertificate"]["serialNumber"])
    hex_serial = "%X" % serial
    if len(hex_serial) % 2:
        hex_serial = "0" + hex_serial
    return "serial=" + hex_serial


def cert_sha1_fingerprint(dsc_der):
    """Return the SHA-1 fingerprint, mirroring ``openssl x509 -fingerprint``."""
    digest = hashlib.sha1(dsc_der).hexdigest().upper()
    pairs = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    return "SHA1 Fingerprint=" + pairs


# --------------------------------------------------------------------------- #
# ASN.1 structure dump (replaces ``openssl asn1parse``)
# --------------------------------------------------------------------------- #

_UNIVERSAL_TAGS = {
    0x01: "BOOLEAN", 0x02: "INTEGER", 0x03: "BIT STRING", 0x04: "OCTET STRING",
    0x05: "NULL", 0x06: "OBJECT", 0x0A: "ENUMERATED", 0x0C: "UTF8STRING",
    0x10: "SEQUENCE", 0x11: "SET", 0x13: "PRINTABLESTRING", 0x14: "T61STRING",
    0x16: "IA5STRING", 0x17: "UTCTIME", 0x18: "GENERALIZEDTIME",
}
_STRING_TAGS = {0x0C, 0x13, 0x14, 0x16, 0x17, 0x18}


def _decode_oid(content):
    if not content:
        return ""
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _primitive_value(tagnum, content):
    if tagnum == 0x06:
        oid = _decode_oid(content)
        name = _OID_NAMES.get(oid)
        return oid + (" (" + name + ")" if name else "")
    if tagnum == 0x02:  # INTEGER
        return "0x" + content.hex().upper() if content else "0"
    if tagnum in _STRING_TAGS:
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return content.hex().upper()
    return ""


def asn1_dump(der):
    """Render a DER blob as an indented ASN.1 structure (``openssl asn1parse`` style)."""
    lines = []

    def walk(data, start, depth):
        idx = 0
        while idx < len(data):
            offset = start + idx
            tag = data[idx]
            constructed = bool(tag & 0x20)
            tagnum = tag & 0x1F
            header = 1
            if tagnum == 0x1F:  # multi-byte tag number
                tagnum = 0
                while True:
                    byte = data[idx + header]
                    tagnum = (tagnum << 7) | (byte & 0x7F)
                    header += 1
                    if not byte & 0x80:
                        break
            length_byte = data[idx + header]
            header += 1
            if length_byte & 0x80:
                count = length_byte & 0x7F
                length = int.from_bytes(data[idx + header:idx + header + count], "big")
                header += count
            else:
                length = length_byte
            content = data[idx + header:idx + header + length]

            if tag & 0xC0:  # context/application/private class
                label = "cont [ %d ]" % tagnum if (tag & 0xC0) == 0x80 else "tag [ %d ]" % tagnum
            else:
                label = _UNIVERSAL_TAGS.get(tagnum, "tag(%d)" % tagnum)
            kind = "cons" if constructed else "prim"
            line = "%5d:d=%d  hl=%d l=%4d %s: %s" % (offset, depth, header, length, kind, label)
            if not constructed:
                value = _primitive_value(tagnum, content)
                if value:
                    line += "        :" + value
            lines.append(line)

            if constructed:
                walk(content, offset + header, depth + 1)
            idx += header + length

    walk(der, 0, 0)
    return "\n".join(lines)
