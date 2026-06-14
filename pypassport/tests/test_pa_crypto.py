"""Unit tests for the pure-Python verification crypto (pypassport.pa_crypto).

These exercise the code paths that used to shell out to the ``openssl`` binary:
CMS SignedData extraction, X.509 chain verification (RSA + ECDSA), the raw RSA
public-key transform used by Active Authentication, and the display helpers.

Fixtures (CA / DSC certificates and an EF.SOD) are built programmatically with
pyasn1 + pycryptodome + ecdsa, so no external tooling or recorded card is needed.
"""

import datetime
import hashlib

import pytest

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import char, univ, useful
from pyasn1_modules import rfc5280, rfc5652

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

import ecdsa
from ecdsa.util import sigencode_der

from pypassport import pa_crypto


_LDS_SECURITY_OBJECT_OID = "2.23.136.1.1.1"
_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"


# --------------------------------------------------------------------------- #
# Minimal X.509 / CMS builders
# --------------------------------------------------------------------------- #

def _name(common_name):
    atv = rfc5280.AttributeTypeAndValue()
    atv["type"] = univ.ObjectIdentifier("2.5.4.3")  # commonName
    atv["value"] = der_encode(char.PrintableString(common_name))
    rdn = rfc5280.RelativeDistinguishedName()
    rdn.setComponentByPosition(0, atv)
    rdn_sequence = rfc5280.RDNSequence()
    rdn_sequence.setComponentByPosition(0, rdn)
    name = rfc5280.Name()
    name.setComponentByName("rdnSequence", rdn_sequence)
    return name


def _algid(oid):
    algid = rfc5280.AlgorithmIdentifier()
    algid["algorithm"] = univ.ObjectIdentifier(oid)
    return algid


def _validity(days_before=1, days_after=365):
    now = datetime.datetime.now(datetime.timezone.utc)
    validity = rfc5280.Validity()
    not_before = rfc5280.Time()
    not_before["utcTime"] = useful.UTCTime.fromDateTime(now - datetime.timedelta(days=days_before))
    not_after = rfc5280.Time()
    not_after["utcTime"] = useful.UTCTime.fromDateTime(now + datetime.timedelta(days=days_after))
    validity["notBefore"] = not_before
    validity["notAfter"] = not_after
    return validity


def _build_cert(subject_cn, issuer_cn, subject_spki_der, sig_oid, sign_func, validity=(1, 365)):
    tbs = rfc5280.TBSCertificate()
    tbs["version"] = 2  # v3
    tbs["serialNumber"] = 4660
    tbs["signature"] = _algid(sig_oid)
    tbs["issuer"] = _name(issuer_cn)
    tbs["validity"] = _validity(*validity)
    tbs["subject"] = _name(subject_cn)
    spki, _ = der_decode(subject_spki_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    tbs["subjectPublicKeyInfo"] = spki

    signature = sign_func(der_encode(tbs))

    cert = rfc5280.Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = _algid(sig_oid)
    cert["signature"] = univ.BitString.fromOctetString(signature)
    return der_encode(cert)


def _rsa_signer(key):
    return lambda tbs: pkcs1_15.new(key).sign(SHA256.new(tbs))


def _ecdsa_signer(key):
    return lambda tbs: key.sign_deterministic(tbs, hashfunc=hashlib.sha256, sigencode=sigencode_der)


def _build_sod(econtent, dsc_der):
    signed_data = rfc5652.SignedData()
    signed_data["version"] = 3

    eci = rfc5652.EncapsulatedContentInfo()
    eci["eContentType"] = univ.ObjectIdentifier(_LDS_SECURITY_OBJECT_OID)
    eci["eContent"] = econtent
    signed_data["encapContentInfo"] = eci

    cert, _ = der_decode(dsc_der, asn1Spec=rfc5280.Certificate())
    choice = rfc5652.CertificateChoices()
    choice["certificate"] = cert
    signed_data["certificates"][0] = choice

    content_info = rfc5652.ContentInfo()
    content_info["contentType"] = rfc5652.id_signedData
    content_info["content"] = der_encode(signed_data)
    return der_encode(content_info)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def rsa_chain():
    ca_key = RSA.generate(2048)
    dsc_key = RSA.generate(2048)
    ca_der = _build_cert("Test CSCA", "Test CSCA",
                         ca_key.publickey().export_key(format="DER"),
                         _SHA256_WITH_RSA, _rsa_signer(ca_key))
    dsc_der = _build_cert("Test DSC", "Test CSCA",
                          dsc_key.publickey().export_key(format="DER"),
                          _SHA256_WITH_RSA, _rsa_signer(ca_key))
    return {"ca_der": ca_der, "dsc_der": dsc_der, "ca_key": ca_key}


@pytest.fixture(scope="module")
def ecdsa_chain():
    ca_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    dsc_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    ca_der = _build_cert("EC CSCA", "EC CSCA", ca_key.get_verifying_key().to_der(),
                         _ECDSA_WITH_SHA256, _ecdsa_signer(ca_key))
    dsc_der = _build_cert("EC DSC", "EC CSCA", dsc_key.get_verifying_key().to_der(),
                          _ECDSA_WITH_SHA256, _ecdsa_signer(ca_key))
    return {"ca_der": ca_der, "dsc_der": dsc_der}


def _write_csca(tmp_path, ca_der, name="csca.der"):
    path = tmp_path / name
    path.write_bytes(ca_der)
    return str(tmp_path)


# --------------------------------------------------------------------------- #
# Chain verification
# --------------------------------------------------------------------------- #

def test_verify_rsa_chain_ok(rsa_chain, tmp_path):
    csca_dir = _write_csca(tmp_path, rsa_chain["ca_der"])
    assert pa_crypto.verify_certificate_chain(rsa_chain["dsc_der"], csca_dir) is True


def test_verify_ecdsa_chain_ok(ecdsa_chain, tmp_path):
    csca_dir = _write_csca(tmp_path, ecdsa_chain["ca_der"])
    assert pa_crypto.verify_certificate_chain(ecdsa_chain["dsc_der"], csca_dir) is True


def test_verify_csca_in_pem_form(rsa_chain, tmp_path):
    # Trust store may hold PEM files, not just DER.
    pem = pa_crypto.dsc_der_to_pem(rsa_chain["ca_der"])
    (tmp_path / "csca.pem").write_bytes(pem)
    assert pa_crypto.verify_certificate_chain(rsa_chain["dsc_der"], str(tmp_path)) is True


def test_verify_no_matching_issuer(rsa_chain, ecdsa_chain, tmp_path):
    # Only an unrelated CA is present.
    csca_dir = _write_csca(tmp_path, ecdsa_chain["ca_der"])
    with pytest.raises(pa_crypto.ChainVerificationError):
        pa_crypto.verify_certificate_chain(rsa_chain["dsc_der"], csca_dir)


def test_verify_bad_signature(tmp_path):
    real_ca = RSA.generate(2048)
    attacker = RSA.generate(2048)
    ca_der = _build_cert("Rogue CSCA", "Rogue CSCA",
                         real_ca.publickey().export_key(format="DER"),
                         _SHA256_WITH_RSA, _rsa_signer(real_ca))
    # DSC claims to be issued by "Rogue CSCA" but is signed by the attacker key.
    dsc_der = _build_cert("Bad DSC", "Rogue CSCA",
                          RSA.generate(2048).publickey().export_key(format="DER"),
                          _SHA256_WITH_RSA, _rsa_signer(attacker))
    csca_dir = _write_csca(tmp_path, ca_der)
    with pytest.raises(pa_crypto.ChainVerificationError):
        pa_crypto.verify_certificate_chain(dsc_der, csca_dir)


def test_verify_expired(tmp_path):
    ca_key = RSA.generate(2048)
    ca_der = _build_cert("Exp CSCA", "Exp CSCA",
                         ca_key.publickey().export_key(format="DER"),
                         _SHA256_WITH_RSA, _rsa_signer(ca_key))
    dsc_der = _build_cert("Exp DSC", "Exp CSCA",
                          RSA.generate(2048).publickey().export_key(format="DER"),
                          _SHA256_WITH_RSA, _rsa_signer(ca_key), validity=(400, -10))
    csca_dir = _write_csca(tmp_path, ca_der)
    with pytest.raises(pa_crypto.ChainVerificationError):
        pa_crypto.verify_certificate_chain(dsc_der, csca_dir)


# --------------------------------------------------------------------------- #
# CMS / EF.SOD extraction
# --------------------------------------------------------------------------- #

def test_extract_eContent_and_dsc(rsa_chain):
    econtent = b"\x30\x03\x02\x01\x07"  # arbitrary DER payload standing in for the LDS object
    sod = _build_sod(econtent, rsa_chain["dsc_der"])

    assert pa_crypto.extract_eContent(sod) == econtent

    extracted = pa_crypto.extract_dsc_der(sod)
    assert extracted == rsa_chain["dsc_der"]
    # And it parses back as a certificate.
    der_decode(extracted, asn1Spec=rfc5280.Certificate())


# --------------------------------------------------------------------------- #
# Raw RSA (Active Authentication) and public-key rendering
# --------------------------------------------------------------------------- #

def test_raw_rsa_roundtrip():
    key = RSA.generate(1024)
    k = (key.n.bit_length() + 7) // 8
    spki = key.publickey().export_key(format="DER")

    message = 0x6A11223344
    cipher = pow(message, key.d, key.n)  # "sign" with the private exponent
    recovered = pa_crypto.raw_rsa(spki, cipher.to_bytes(k, "big"))

    assert recovered == message.to_bytes(k, "big")
    assert len(recovered) == k  # full modulus-length block (leading zeros preserved)


def test_rsa_pubkey_to_pem_roundtrips():
    key = RSA.generate(1024)
    spki = key.publickey().export_key(format="DER")
    pem = pa_crypto.rsa_pubkey_to_pem(spki)
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    reimported = RSA.import_key(pem)
    assert reimported.n == key.n
    assert reimported.e == key.e


# --------------------------------------------------------------------------- #
# Display helpers
# --------------------------------------------------------------------------- #

def test_cert_serial_and_fingerprint(rsa_chain):
    dsc_der = rsa_chain["dsc_der"]
    assert pa_crypto.cert_serial(dsc_der) == "serial=1234"  # 4660 == 0x1234

    expected = hashlib.sha1(dsc_der).hexdigest().upper()
    fingerprint = pa_crypto.cert_sha1_fingerprint(dsc_der)
    assert fingerprint.startswith("SHA1 Fingerprint=")
    assert fingerprint.replace("SHA1 Fingerprint=", "").replace(":", "") == expected


def test_asn1_dump_structure(rsa_chain):
    dump = pa_crypto.asn1_dump(rsa_chain["dsc_der"])
    assert dump.splitlines()[0].endswith("SEQUENCE")  # a Certificate is a SEQUENCE
    assert "OBJECT" in dump  # signature algorithm OID is rendered
