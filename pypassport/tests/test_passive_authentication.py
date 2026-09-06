"""Tests for native (OpenSSL-free) Passive Authentication.

A throwaway PKI (CSCA + DSC) and a CMS EF.SOD are synthesised in-process so the
whole verification path — CMS parsing, SOD signature verification, DSC->CSCA
chain validation and DG-hash comparison — is exercised without any real
passport data or external tooling.

Everything is built with the same libraries the library itself uses
(pycryptodome + pyasn1 / pyasn1-modules), so the tests both exercise the
verification code and prove the chosen stack can emit conformant DER.
"""

import datetime
import hashlib

import pytest

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import char, namedtype, univ, useful
from pyasn1_modules import rfc5280, rfc5652

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from ecdsa import BRAINPOOLP256r1, SigningKey
from ecdsa.util import sigencode_der

from pypassport import asn1
from pypassport.ca_manager import CAManager, CAManagerException
from pypassport.doc9303 import cms
from pypassport.doc9303 import data_group
from pypassport.doc9303.passive_authentication import (
    PassiveAuthentication,
    PassiveAuthenticationException,
)


# --- synthetic PKI / SOD builder --------------------------------------------

_COMMON_NAME = univ.ObjectIdentifier("2.5.4.3")
_SHA256_RSA = univ.ObjectIdentifier("1.2.840.113549.1.1.11")  # sha256WithRSAEncryption
_RSA_ENC = univ.ObjectIdentifier("1.2.840.113549.1.1.1")  # rsaEncryption
_SHA256 = univ.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
_ID_LDS_SO = univ.ObjectIdentifier("2.23.136.1.1.1")  # id-icao-ldsSecurityObject
_ID_CSCA_MASTER_LIST = univ.ObjectIdentifier("2.23.136.1.1.2")


class _CscaMasterList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("certList", univ.SetOf(componentType=univ.Any())),
    )


def _name(common_name):
    atv = rfc5280.AttributeTypeAndValue()
    atv["type"] = _COMMON_NAME
    atv["value"] = univ.Any(der_encode(char.PrintableString(common_name)))
    rdn = rfc5280.RelativeDistinguishedName()
    rdn.setComponentByPosition(0, atv)
    rdn_seq = rfc5280.RDNSequence()
    rdn_seq.setComponentByPosition(0, rdn)
    name = rfc5280.Name()
    name.setComponentByName("rdnSequence", rdn_seq)
    return name


def _alg(oid):
    alg = rfc5280.AlgorithmIdentifier()
    alg["algorithm"] = oid
    alg["parameters"] = univ.Any(der_encode(univ.Null()))
    return alg


def _time(dt):
    t = rfc5280.Time()
    t.setComponentByName("utcTime", useful.UTCTime.fromDateTime(dt))
    return t


def _make_certificate(subject_cn, subject_key, issuer_cn, issuer_key, serial):
    now = datetime.datetime.now(datetime.timezone.utc)
    spki, _ = der_decode(subject_key.publickey().export_key(format="DER"), asn1Spec=rfc5280.SubjectPublicKeyInfo())

    tbs = rfc5280.TBSCertificate()
    tbs["version"] = "v3"
    tbs["serialNumber"] = serial
    tbs["signature"] = _alg(_SHA256_RSA)
    tbs["issuer"] = _name(issuer_cn)
    validity = rfc5280.Validity()
    validity["notBefore"] = _time(now - datetime.timedelta(days=1))
    validity["notAfter"] = _time(now + datetime.timedelta(days=3650))
    tbs["validity"] = validity
    tbs["subject"] = _name(subject_cn)
    tbs["subjectPublicKeyInfo"] = spki

    signature = pkcs1_15.new(issuer_key).sign(SHA256.new(der_encode(tbs)))

    cert = rfc5280.Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = _alg(_SHA256_RSA)
    cert["signature"] = univ.BitString.fromOctetString(signature)
    return der_encode(cert)


def _make_lds_security_object(dg_hashes):
    lso = asn1.LDSSecurityObject()
    lso["version"] = "V0"
    lso["hashAlgorithm"]["algorithm"] = _SHA256
    values = asn1.DataGroupHashValues()
    for i, (number, digest) in enumerate(sorted(dg_hashes.items())):
        entry = asn1.DataGroupHash()
        entry["dataGroupNumber"] = number
        entry["dataGroupHashValue"] = univ.OctetString(digest)
        values.setComponentByPosition(i, entry)
    lso["dataGroupHashValues"] = values
    return der_encode(lso)


def _attribute(attr_type, value_der):
    attr = rfc5652.Attribute()
    attr["attrType"] = attr_type
    attr["attrValues"].setComponentByPosition(0, univ.Any(value_der))
    return attr


def _make_signed_data(econtent_type, econtent, signer_der, signer_key, issuer_cn, signer_serial):
    encap = rfc5652.EncapsulatedContentInfo()
    encap["eContentType"] = econtent_type
    encap["eContent"] = econtent

    message_digest = SHA256.new(econtent).digest()
    content_type_attr = _attribute(rfc5652.id_contentType, der_encode(econtent_type))
    digest_attr = _attribute(rfc5652.id_messageDigest, der_encode(univ.OctetString(message_digest)))

    # Standalone SET OF for the signature computation (tag 0x31).
    signing_attrs = rfc5652.SignedAttributes()
    signing_attrs.setComponentByPosition(0, content_type_attr)
    signing_attrs.setComponentByPosition(1, digest_attr)
    signature = pkcs1_15.new(signer_key).sign(SHA256.new(der_encode(signing_attrs)))

    signer = rfc5652.SignerInfo()
    signer["version"] = "v1"
    ias = rfc5652.IssuerAndSerialNumber()
    ias["issuer"] = _name(issuer_cn)
    ias["serialNumber"] = signer_serial
    signer["sid"].setComponentByName("issuerAndSerialNumber", ias)
    signer["digestAlgorithm"] = _alg(_SHA256)
    signer["signedAttrs"].setComponentByPosition(0, content_type_attr)
    signer["signedAttrs"].setComponentByPosition(1, digest_attr)
    signer["signatureAlgorithm"] = _alg(_RSA_ENC)
    signer["signature"] = univ.OctetString(signature)

    signed_data = rfc5652.SignedData()
    signed_data["version"] = "v3"
    signed_data["digestAlgorithms"].setComponentByPosition(0, _alg(_SHA256))
    signed_data["encapContentInfo"] = encap
    choice = rfc5652.CertificateChoices()
    choice.setComponentByName("certificate", der_decode(signer_der, asn1Spec=rfc5280.Certificate())[0])
    signed_data["certificates"].setComponentByPosition(0, choice)
    signed_data["signerInfos"].setComponentByPosition(0, signer)

    content_info = rfc5652.ContentInfo()
    content_info["contentType"] = rfc5652.id_signedData
    content_info["content"] = univ.Any(der_encode(signed_data))
    return der_encode(content_info)


def _make_sod(lds_der, dsc_der, dsc_key, csca_cn, dsc_serial):
    return _make_signed_data(_ID_LDS_SO, lds_der, dsc_der, dsc_key, csca_cn, dsc_serial)


def _make_master_list(csca_ders, signer_der, signer_key, issuer_cn, signer_serial):
    master_list = _CscaMasterList()
    master_list["version"] = 0
    for i, csca_der in enumerate(csca_ders):
        master_list["certList"].setComponentByPosition(i, univ.Any(csca_der))
    return _make_signed_data(
        _ID_CSCA_MASTER_LIST,
        der_encode(master_list),
        signer_der,
        signer_key,
        issuer_cn,
        signer_serial,
    )


def build_pki(dg_hashes):
    csca_key = RSA.generate(2048)
    dsc_key = RSA.generate(2048)
    csca_cn, dsc_cn = "Test CSCA", "Test DSC"
    csca_der = _make_certificate(csca_cn, csca_key, csca_cn, csca_key, serial=1)
    dsc_der = _make_certificate(dsc_cn, dsc_key, csca_cn, csca_key, serial=42)
    lds_der = _make_lds_security_object(dg_hashes)
    sod_der = _make_sod(lds_der, dsc_der, dsc_key, csca_cn, dsc_serial=42)
    return {
        "csca_der": csca_der,
        "dsc_der": dsc_der,
        "dsc_key": dsc_key,
        "lds_der": lds_der,
        "sod_der": sod_der,
    }


# DG1 -> tag "61", DG2 -> tag "75" (see doc9303/converter.py).
DG_CONTENTS = {1: b"\x61\x05DG1!!", 2: b"\x75\x05DG2!!"}
DG_TAGS = {1: "61", 2: "75"}


class _FakeDG:
    def __init__(self, tag, file):
        self.tag = tag
        self.file = file


@pytest.fixture
def pki():
    dg_hashes = {n: hashlib.sha256(c).digest() for n, c in DG_CONTENTS.items()}
    return build_pki(dg_hashes)


def _make_sod_object(sod_der):
    sod = data_group.SOD.__new__(data_group.SOD)
    sod._body = sod_der  # set the backing attribute directly (bypass TLV parsing)
    return sod


def _csca_dir(tmp_path, csca_der, name="csca.cer"):
    (tmp_path / name).write_bytes(csca_der)
    return CAManager(str(tmp_path))


# --- low-level cms module ---------------------------------------------------


def test_parse_sod_fields(pki):
    info = cms.parse_sod(pki["sod_der"])
    assert info.econtent == pki["lds_der"]
    assert info.econtent_type == "2.23.136.1.1.1"  # id-ldsSecurityObject
    assert info.digest_algorithm == "2.16.840.1.101.3.4.2.1"  # sha256
    assert info.signature_algorithm == "1.2.840.113549.1.1.1"  # rsaEncryption
    assert info.signed_attrs_der[0] == 0x31  # re-tagged SET OF


def test_verify_sod_signature_ok(pki):
    assert cms.verify_sod_signature(cms.parse_sod(pki["sod_der"])) is True


def test_verify_chain_ok(pki):
    assert cms.verify_chain(pki["dsc_der"], [pki["csca_der"]]) is True


def test_verify_chain_wrong_csca(pki):
    other = build_pki({1: hashlib.sha256(b"x").digest(), 2: hashlib.sha256(b"y").digest()})
    with pytest.raises(cms.CMSVerificationException):
        cms.verify_chain(pki["dsc_der"], [other["csca_der"]])


def test_verify_sod_signature_tampered(pki):
    bad = bytearray(pki["sod_der"])
    bad[-1] ^= 0xFF  # corrupt the trailing signature byte
    info = cms.parse_sod(bytes(bad))  # structure still parses
    with pytest.raises(cms.CMSVerificationException):
        cms.verify_sod_signature(info)


def test_certificate_helpers(pki):
    pem = cms.certificate_to_pem(pki["dsc_der"])
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert cms.load_certificate_der(pem) == pki["dsc_der"]
    assert cms.certificate_serial(pki["dsc_der"]) == 42
    fp = cms.certificate_sha1_fingerprint(pki["dsc_der"])
    assert len(fp) == 59 and fp.count(":") == 19  # 20 bytes, hex, colon-separated


# --- PassiveAuthentication high-level API ------------------------------------


def test_get_sod_content_and_certificate(pki):
    pa = PassiveAuthentication()
    sod = _make_sod_object(pki["sod_der"])
    assert pa.get_sod_content(sod) == pki["lds_der"]
    assert pa.get_certificate(sod).startswith(b"-----BEGIN CERTIFICATE-----")


def test_verify_sod_and_cds_ok(pki, tmp_path):
    pa = PassiveAuthentication()
    sod = _make_sod_object(pki["sod_der"])
    csca = _csca_dir(tmp_path, pki["csca_der"])
    assert pa.verify_sod_and_cds(sod, csca) is True
    assert pa.verification_info is not None
    assert pa.verification_info["document_signer_certificate"]["subject"]["CN"] == "Test DSC"
    assert pa.verification_info["country_signing_ca_certificate"]["subject"]["CN"] == "Test CSCA"
    assert pa.verification_info["sod"]["digest_algorithm"] == "sha256"
    assert pa.verification_info["document_signer_certificate"]["sha256_fingerprint"]


def test_verify_sod_and_cds_untrusted_csca(pki, tmp_path):
    other = build_pki({1: hashlib.sha256(b"a").digest(), 2: hashlib.sha256(b"b").digest()})
    pa = PassiveAuthentication()
    sod = _make_sod_object(pki["sod_der"])
    csca = _csca_dir(tmp_path, other["csca_der"])
    with pytest.raises(PassiveAuthenticationException):
        pa.verify_sod_and_cds(sod, csca)


def test_verify_sod_and_cds_bad_signature(pki, tmp_path):
    bad = bytearray(pki["sod_der"])
    bad[-1] ^= 0xFF
    pa = PassiveAuthentication()
    sod = _make_sod_object(bytes(bad))
    csca = _csca_dir(tmp_path, pki["csca_der"])
    with pytest.raises(PassiveAuthenticationException):
        pa.verify_sod_and_cds(sod, csca)


def test_execute_pa_integrity(pki):
    pa = PassiveAuthentication()
    sod = _make_sod_object(pki["sod_der"])
    dgs = [_FakeDG(DG_TAGS[n], DG_CONTENTS[n]) for n in DG_CONTENTS]
    result = pa.execute_pa(sod, dgs)
    assert result == {"DG1": True, "DG2": True}


def test_execute_pa_detects_tampered_dg(pki):
    pa = PassiveAuthentication()
    sod = _make_sod_object(pki["sod_der"])
    dgs = [_FakeDG(DG_TAGS[1], DG_CONTENTS[1]), _FakeDG(DG_TAGS[2], b"\x75\x05TAMPR")]
    result = pa.execute_pa(sod, dgs)
    assert result["DG1"] is True
    assert result["DG2"] is False


def test_camanager_no_certificate(tmp_path):
    with pytest.raises(CAManagerException):
        CAManager(str(tmp_path)).get_certificates()


# --- EC / Brainpool Document Signers (national PKI, explicit params) ----------
#
# pycryptodome cannot import Brainpool curves nor EC keys carrying explicit
# domain parameters (it raises "Not an ECC DER key" / "Unsupported ECC curve").
# Such keys are exactly what national DSC/CSCA certificates use (e.g. Belgium),
# so the verification path must fall back to the ``ecdsa`` library.

_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"


def _ec_spki(verifying_key, params_encoding):
    der = verifying_key.to_der(curve_parameters_encoding=params_encoding)
    spki, _ = der_decode(der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    return spki


def _ec_sig_alg():
    alg = rfc5280.AlgorithmIdentifier()
    alg["algorithm"] = univ.ObjectIdentifier(_ECDSA_WITH_SHA256)  # parameters absent
    return alg


def _make_ec_certificate(subject_cn, subject_sk, issuer_cn, issuer_sk, serial, params_encoding):
    now = datetime.datetime.now(datetime.timezone.utc)
    tbs = rfc5280.TBSCertificate()
    tbs["version"] = "v3"
    tbs["serialNumber"] = serial
    tbs["signature"] = _ec_sig_alg()
    tbs["issuer"] = _name(issuer_cn)
    validity = rfc5280.Validity()
    validity["notBefore"] = _time(now - datetime.timedelta(days=1))
    validity["notAfter"] = _time(now + datetime.timedelta(days=3650))
    tbs["validity"] = validity
    tbs["subject"] = _name(subject_cn)
    tbs["subjectPublicKeyInfo"] = _ec_spki(subject_sk.get_verifying_key(), params_encoding)

    signature = issuer_sk.sign_deterministic(der_encode(tbs), hashfunc=hashlib.sha256, sigencode=sigencode_der)
    cert = rfc5280.Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = _ec_sig_alg()
    cert["signature"] = univ.BitString.fromOctetString(signature)
    return der_encode(cert)


@pytest.fixture(params=["named_curve", "explicit"])
def ec_params(request):
    return request.param


def test_verify_signature_ecdsa_ok(ec_params):
    sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    spki_der = der_encode(_ec_spki(sk.get_verifying_key(), ec_params))
    message = b"the signed LDS security object"
    sig = sk.sign_deterministic(message, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    # Returns None on success; raises on failure.
    assert cms._verify_signature(spki_der, _ECDSA_WITH_SHA256, sig, message) is None


def test_verify_signature_ecdsa_tampered(ec_params):
    sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    spki_der = der_encode(_ec_spki(sk.get_verifying_key(), ec_params))
    sig = sk.sign_deterministic(b"message", hashfunc=hashlib.sha256, sigencode=sigencode_der)
    with pytest.raises(cms.CMSVerificationException):
        cms._verify_signature(spki_der, _ECDSA_WITH_SHA256, sig, b"a different message")


def test_verify_chain_ec_ok(ec_params):
    csca_sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    dsc_sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    csca = _make_ec_certificate("EC CSCA", csca_sk, "EC CSCA", csca_sk, 1, ec_params)
    dsc = _make_ec_certificate("EC DSC", dsc_sk, "EC CSCA", csca_sk, 7, ec_params)
    assert cms.verify_chain(dsc, [csca]) is True


def test_verify_chain_ec_untrusted(ec_params):
    csca_sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    other_sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    dsc_sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    dsc = _make_ec_certificate("EC DSC", dsc_sk, "EC CSCA", csca_sk, 7, ec_params)
    # Same issuer name, different (untrusted) key — the signature must not verify.
    other = _make_ec_certificate("EC CSCA", other_sk, "EC CSCA", other_sk, 1, ec_params)
    with pytest.raises(cms.CMSVerificationException):
        cms.verify_chain(dsc, [other])


# --- robust certificate loading (PEM with surrounding text, bundles, junk) ----


def _pem_with_text(der, label="CERTIFICATE"):
    """A PEM block wrapped in descriptive text, as PKI distributions often ship."""
    import base64
    import textwrap

    b64 = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return (
        b"Certificate of the Test CSCA\n"
        b"Issuer: C=XX, CN=Test CSCA\n"
        + f"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n".encode("ascii")
        + b"(end of certificate)\n"
    )


def test_load_certificates_pem_with_surrounding_text(pki):
    # Reproduces the exact failure: text around the PEM block corrupted the
    # old loader and yielded an application-tagged blob (tag 64:0:3).
    certs = cms.load_certificates(_pem_with_text(pki["csca_der"]))
    assert certs == [pki["csca_der"]]


def test_load_certificates_bundle(pki):
    blob = _pem_with_text(pki["csca_der"]) + _pem_with_text(pki["dsc_der"])
    assert cms.load_certificates(blob) == [pki["csca_der"], pki["dsc_der"]]


def test_load_certificates_der_passthrough(pki):
    assert cms.load_certificates(pki["csca_der"]) == [pki["csca_der"]]


def test_load_master_list_certificates_uses_inner_csca_set_only(pki):
    master_list = _make_master_list([pki["csca_der"]], pki["dsc_der"], pki["dsc_key"], "Test CSCA", 42)
    assert cms.load_master_list_certificates(master_list, [pki["dsc_der"]]) == [pki["csca_der"]]


def test_load_master_list_certificates_rejects_unanchored_signer(pki):
    master_list = _make_master_list([pki["csca_der"]], pki["dsc_der"], pki["dsc_key"], "Test CSCA", 42)
    with pytest.raises(cms.CMSVerificationException, match="Signer trust anchors"):
        cms.load_master_list_certificates(master_list)


def test_load_master_list_rejects_other_signed_data(pki):
    with pytest.raises(cms.CMSVerificationException):
        cms.load_master_list_certificates(pki["sod_der"])


def test_parse_certificate_rejects_junk_cleanly():
    # A non-certificate must raise a clean exception, not dump the ASN.1 schema.
    with pytest.raises(cms.CMSVerificationException):
        cms._parse_certificate(b"\x43\x65\x72 this is not a certificate")
    assert cms.is_certificate(b"nope") is False


def test_camanager_skips_non_certificate_files(pki, tmp_path):
    (tmp_path / "CSCA.pem").write_bytes(_pem_with_text(pki["csca_der"]))
    (tmp_path / "notes.crt").write_text("just a description, not a certificate")
    certs = CAManager(str(tmp_path)).get_certificates()
    assert certs == [pki["csca_der"]]


def test_camanager_loads_icao_master_list_for_passive_authentication(pki, tmp_path):
    master_list = _make_master_list([pki["csca_der"]], pki["dsc_der"], pki["dsc_key"], "Test CSCA", 42)
    (tmp_path / "icao.ml").write_bytes(master_list)

    pa = PassiveAuthentication()
    sod = _make_sod_object(pki["sod_der"])
    assert pa.verify_sod_and_cds(sod, CAManager(str(tmp_path), master_list_signers=[pki["dsc_der"]])) is True


def test_verify_chain_skips_non_certificate_in_store(pki):
    # A stray non-certificate entry must not abort verification.
    assert cms.verify_chain(pki["dsc_der"], [b"junk file contents", pki["csca_der"]]) is True
