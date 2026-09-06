"""Native (library-only) replacements for the crypto operations that pypassport
used to delegate to the OpenSSL command-line binary.

This module covers everything the old ``openssl.py`` wrapper and the scattered
``subprocess`` calls did on the *reading/verification* path:

* **CMS / RFC 5652 SignedData** parsing and verification for EF.SOD
  (Passive Authentication) — replaces ``openssl smime`` / ``openssl pkcs7``.
* **X.509** certificate parsing, PEM/DER handling, serial/fingerprint
  extraction and DSC -> CSCA chain verification — replaces
  ``openssl verify -CApath`` and the ``openssl x509`` diagnostics.
* **Raw RSA public-key recovery** for Active Authentication and the
  sign-everything attack — replaces ``openssl rsautl -raw -verify``.

It relies only on libraries that are already pypassport dependencies:
``pyasn1`` / ``pyasn1-modules`` for ASN.1 and ``pycryptodome`` for the RSA/ECDSA
primitives. No external binary is required.
"""

import base64
import hmac
import textwrap
from datetime import datetime, timezone
from typing import Any

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ
from pyasn1_modules import rfc4055, rfc5280, rfc5652

from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15, pss

from ecdsa import BadSignatureError, VerifyingKey
from ecdsa.util import sigdecode_der

from pypassport.der_object_identifier import OID


class CMSVerificationException(Exception):
    pass


# --- Algorithm OID tables ---------------------------------------------------

# Message-digest / hash OIDs -> pycryptodome hash module.
_HASH_BY_OID = {
    "1.3.14.3.2.26": SHA1,
    "2.16.840.1.101.3.4.2.4": SHA224,
    "2.16.840.1.101.3.4.2.1": SHA256,
    "2.16.840.1.101.3.4.2.2": SHA384,
    "2.16.840.1.101.3.4.2.3": SHA512,
    # RSA-with-hash signature OIDs carry the hash too.
    "1.2.840.113549.1.1.5": SHA1,
    "1.2.840.113549.1.1.14": SHA224,
    "1.2.840.113549.1.1.11": SHA256,
    "1.2.840.113549.1.1.12": SHA384,
    "1.2.840.113549.1.1.13": SHA512,
    # ECDSA-with-hash signature OIDs.
    "1.2.840.10045.4.1": SHA1,
    "1.2.840.10045.4.3.1": SHA224,
    "1.2.840.10045.4.3.2": SHA256,
    "1.2.840.10045.4.3.3": SHA384,
    "1.2.840.10045.4.3.4": SHA512,
}

_RSA_PKCS1_OIDS = {
    "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.14",
    "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12",
    "1.2.840.113549.1.1.13",
}
_ECDSA_OIDS = {
    "1.2.840.10045.4.1",
    "1.2.840.10045.4.3.1",
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.10045.4.3.4",
}
_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"  # rsaEncryption (generic)
_RSA_PSS_OID = "1.2.840.113549.1.1.10"
_ICAO_CSCA_MASTER_LIST_OID = "2.23.136.1.1.2"


# --- CMS / EF.SOD -----------------------------------------------------------


class SignedDataInfo:
    """Parsed pieces of a CMS SignedData (EF.SOD) needed for verification."""

    def __init__(
        self, dsc_der, econtent, econtent_type, digest_algorithm, signed_attrs_der, signature_algorithm, signature,
        signature_parameters=None, certificates=(),
    ):
        self.dsc_der = dsc_der  # DER of the Document Signer cert
        self.econtent = econtent  # LDSSecurityObject DER bytes
        self.econtent_type = econtent_type  # OID string
        self.digest_algorithm = digest_algorithm  # OID string (SignerInfo digest)
        self.signed_attrs_der = signed_attrs_der  # SET-OF DER for verify, or None
        self.signature_algorithm = signature_algorithm  # OID string
        self.signature = signature  # signature bytes
        self.signature_parameters = signature_parameters
        self.certificates = tuple(certificates)


class CscaMasterList(univ.Sequence):
    """ICAO Doc 9303 CSCA Master List payload carried inside CMS SignedData.

    The certificate entries are kept as raw DER ``ANY`` values so one malformed
    or non-conformant certificate does not prevent the remaining entries from
    being loaded and filtered individually by the trust-store caller.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("certList", univ.SetOf(componentType=univ.Any())),
    )


def parse_sod(der):
    """Parse an EF.SOD body (CMS ContentInfo, DER) into a :class:`SignedDataInfo`.

    @param der: The SOD body (``sodObj.body``); a DER-encoded CMS ContentInfo.
    @return: A :class:`SignedDataInfo`.
    @raise CMSVerificationException: If the structure is not a SignedData with a
        single signer and an embedded Document Signer certificate.
    """
    # Defensive: strip a leading 0x77 application tag if a raw EF is passed in.
    if der and der[0] == 0x77:
        inner, _ = der_decode(der, asn1Spec=univ.Any())
        der = inner.asOctets()

    try:
        content_info, rest = der_decode(der, asn1Spec=rfc5652.ContentInfo())
    except Exception as exc:
        raise CMSVerificationException("EF.SOD is not a valid CMS ContentInfo: " + str(exc))

    if rest or der_encode(content_info) != bytes(der):
        raise CMSVerificationException("EF.SOD is not one canonical DER ContentInfo")
    if str(content_info["contentType"]) != str(rfc5652.id_signedData):
        raise CMSVerificationException("EF.SOD content type is not id-signedData")

    signed_data, rest = der_decode(content_info["content"].asOctets(), asn1Spec=rfc5652.SignedData())
    if rest or der_encode(signed_data) != content_info["content"].asOctets():
        raise CMSVerificationException("EF.SOD SignedData is not canonical DER")

    signer_infos = signed_data["signerInfos"]
    if len(signer_infos) != 1:
        raise CMSVerificationException(f"EF.SOD must contain exactly one SignerInfo (got {len(signer_infos)})")
    signer_info = signer_infos[0]

    encap = signed_data["encapContentInfo"]
    if not encap["eContent"].isValue:
        raise CMSVerificationException("EF.SOD has no embedded eContent")
    econtent = encap["eContent"].asOctets()
    econtent_type = str(encap["eContentType"])
    if econtent_type != "2.23.136.1.1.1":
        raise CMSVerificationException(f"EF.SOD has unexpected LDS Security Object content type {econtent_type}")

    dsc_der = _find_signer_certificate(signed_data, signer_info)

    digest_algorithm = str(signer_info["digestAlgorithm"]["algorithm"])
    advertised_digests = {str(x["algorithm"]) for x in signed_data["digestAlgorithms"]}
    if digest_algorithm not in advertised_digests:
        raise CMSVerificationException("SignerInfo digestAlgorithm is absent from SignedData.digestAlgorithms")
    signature_algorithm = str(signer_info["signatureAlgorithm"]["algorithm"])
    signature = signer_info["signature"].asOctets()
    signature_parameters = (signer_info["signatureAlgorithm"]["parameters"].asOctets()
                            if signer_info["signatureAlgorithm"]["parameters"].isValue else None)

    signed_attrs_der = None
    if signer_info["signedAttrs"].isValue and len(signer_info["signedAttrs"]) > 0:
        signed_attrs_der = _reencode_signed_attrs(signer_info["signedAttrs"])

    return SignedDataInfo(
        dsc_der, econtent, econtent_type, digest_algorithm, signed_attrs_der, signature_algorithm, signature,
        signature_parameters, _embedded_certificates(signed_data),
    )


def describe_sod(der):
    """Return a human-readable ASN.1 dump of the SOD's SignedData.

    Replaces ``openssl asn1parse`` for the diagnostic / fingerprint output.
    """
    if der and der[0] == 0x77:
        inner, _ = der_decode(der, asn1Spec=univ.Any())
        der = inner.asOctets()
    content_info, _ = der_decode(der, asn1Spec=rfc5652.ContentInfo())
    signed_data, _ = der_decode(content_info["content"].asOctets(), asn1Spec=rfc5652.SignedData())
    return signed_data.prettyPrint()


def verify_sod_signature(info):
    """Verify the Document Signer's signature over the SOD.

    When signed attributes are present (the common case) this checks that the
    ``messageDigest`` attribute matches ``digest(eContent)`` and then verifies
    the signature over the DER-encoded signed attributes. Otherwise the
    signature is verified directly over the eContent.

    @param info: A :class:`SignedDataInfo` from :func:`parse_sod`.
    @return: True if the signature is valid.
    @raise CMSVerificationException: If verification fails.
    """
    spki_der = _spki_der(_parse_certificate(info.dsc_der))

    if info.signed_attrs_der is not None:
        expected = _hash_for_oid(info.digest_algorithm).new(info.econtent).digest()
        actual = _validate_signed_attributes(info.signed_attrs_der, info.econtent_type)
        if not hmac.compare_digest(actual, expected):
            raise CMSVerificationException("SOD messageDigest attribute does not match eContent")
        signed_message = info.signed_attrs_der
    else:
        signed_message = info.econtent

    if (info.signature_algorithm in _HASH_BY_OID
            and _HASH_BY_OID[info.signature_algorithm] is not _HASH_BY_OID.get(info.digest_algorithm)):
        raise CMSVerificationException("Signer digestAlgorithm conflicts with signature algorithm")
    _verify_signature(
        spki_der, info.signature_algorithm, info.signature, signed_message, digest_oid=info.digest_algorithm,
        signature_parameters=info.signature_parameters,
    )
    return True


def _embedded_certificates(signed_data):
    certs = []
    if signed_data["certificates"].isValue:
        certs = [der_encode(x["certificate"]) for x in signed_data["certificates"] if x.getName() == "certificate"]
    return certs


def _find_signer_certificate(signed_data, signer_info):
    """Return the DER of the certificate identified by the SignerInfo (or the
    only embedded certificate)."""
    certs = []
    certs.extend(_embedded_certificates(signed_data))
    if not certs:
        raise CMSVerificationException("EF.SOD does not embed a Document Signer certificate")
    sid = signer_info["sid"]
    if sid.getName() == "issuerAndSerialNumber":
        ias = sid["issuerAndSerialNumber"]
        want_issuer = der_encode(ias["issuer"])
        want_serial = int(ias["serialNumber"])
        for cert_der in certs:
            cert = _parse_certificate(cert_der)
            tbs = cert["tbsCertificate"]
            if der_encode(tbs["issuer"]) == want_issuer and int(tbs["serialNumber"]) == want_serial:
                return cert_der
        raise CMSVerificationException("No embedded certificate exactly matches SignerInfo issuer/serial")
    raise CMSVerificationException("Unsupported or unmatched SignerIdentifier")


def _reencode_signed_attrs(signed_attrs):
    """Re-encode SignerInfo signedAttrs as a universal ``SET OF`` for signing.

    In SignerInfo the attributes carry an IMPLICIT ``[0]`` tag (0xA0); RFC 5652
    requires the *signature* to be computed over the same content re-tagged as a
    universal SET OF (0x31). The DER length octets are identical, so only the
    single-byte tag needs swapping.
    """
    encoded = der_encode(signed_attrs)
    if not encoded or encoded[0] != 0xA0:
        raise CMSVerificationException("Unexpected encoding of SOD signed attributes")
    return b"\x31" + encoded[1:]


def _validate_signed_attributes(signed_attrs_der, econtent_type):
    """Validate the mandatory, single-valued RFC 5652 signed attributes."""
    attrs, rest = der_decode(signed_attrs_der, asn1Spec=rfc5652.SignedAttributes())
    if rest or der_encode(attrs) != signed_attrs_der:
        raise CMSVerificationException("Signed attributes are not canonical DER")
    seen = {}
    for attr in attrs:
        oid = str(attr["attrType"])
        if oid in seen:
            raise CMSVerificationException(f"Duplicate signed attribute {oid}")
        if len(attr["attrValues"]) != 1:
            raise CMSVerificationException(f"Signed attribute {oid} is not single-valued")
        seen[oid] = attr["attrValues"][0].asOctets()
    digest_raw = seen.get(str(rfc5652.id_messageDigest))
    content_raw = seen.get(str(rfc5652.id_contentType))
    if digest_raw is None or content_raw is None:
        raise CMSVerificationException("Signed attributes require contentType and messageDigest")
    digest, rest = der_decode(digest_raw, asn1Spec=univ.OctetString())
    if rest:
        raise CMSVerificationException("Malformed messageDigest attribute")
    content, rest = der_decode(content_raw, asn1Spec=univ.ObjectIdentifier())
    if rest or str(content) != econtent_type:
        raise CMSVerificationException("Signed contentType does not match eContentType")
    return digest.asOctets()


def parse_signed_object(data, *, expected_econtent_type=None, label="CMS object"):
    """Strictly parse any single-signer CMS SignedData object."""
    try:
        ci, rest = der_decode(data, asn1Spec=rfc5652.ContentInfo())
        if rest or der_encode(ci) != bytes(data) or str(ci["contentType"]) != str(rfc5652.id_signedData):
            raise ValueError("non-canonical or wrong content type")
        sd, rest = der_decode(ci["content"].asOctets(), asn1Spec=rfc5652.SignedData())
        if rest or der_encode(sd) != ci["content"].asOctets() or len(sd["signerInfos"]) != 1:
            raise ValueError("SignedData must be canonical and single-signer")
        signer = sd["signerInfos"][0]
        encap = sd["encapContentInfo"]
        econtent_type = str(encap["eContentType"])
        if expected_econtent_type is not None and econtent_type != expected_econtent_type:
            raise ValueError(f"unexpected encapsulated content type {econtent_type}")
        if not encap["eContent"].isValue:
            raise ValueError("detached content is not supported")
        digest_algorithm = str(signer["digestAlgorithm"]["algorithm"])
        if digest_algorithm not in {str(x["algorithm"]) for x in sd["digestAlgorithms"]}:
            raise ValueError("SignerInfo digest absent from digestAlgorithms")
        signed_attrs = (_reencode_signed_attrs(signer["signedAttrs"])
                        if signer["signedAttrs"].isValue and len(signer["signedAttrs"]) else None)
        params = (signer["signatureAlgorithm"]["parameters"].asOctets()
                  if signer["signatureAlgorithm"]["parameters"].isValue else None)
        return SignedDataInfo(
            _find_signer_certificate(sd, signer), encap["eContent"].asOctets(), econtent_type,
            digest_algorithm, signed_attrs, str(signer["signatureAlgorithm"]["algorithm"]),
            signer["signature"].asOctets(), params, _embedded_certificates(sd),
        )
    except CMSVerificationException:
        raise
    except Exception as exc:
        raise CMSVerificationException(f"{label} is not valid strict SignedData: {exc}") from exc


def verify_signed_object(info):
    if info.signed_attrs_der is None:
        raise CMSVerificationException("ICAO signed objects require signed attributes")
    expected = _hash_for_oid(info.digest_algorithm).new(info.econtent).digest()
    actual = _validate_signed_attributes(info.signed_attrs_der, info.econtent_type)
    if not hmac.compare_digest(actual, expected):
        raise CMSVerificationException("CMS messageDigest attribute does not match eContent")
    _verify_signature(_spki_der(_parse_certificate(info.dsc_der)), info.signature_algorithm,
                      info.signature, info.signed_attrs_der, digest_oid=info.digest_algorithm,
                      signature_parameters=info.signature_parameters)
    return True


def load_master_list_certificates(data, trusted_signers=None, *, allow_unverified=False):
    """Extract DER CSCA certificates from an ICAO CSCA Master List.

    A Master List is a CMS ``SignedData`` object whose encapsulated content is a
    ``CscaMasterList`` payload. This parser validates that outer structure and
    returns only the certificates listed inside the payload; the outer signer
    certificate is deliberately not treated as a CSCA trust anchor.

    By default the embedded signer must chain to ``trusted_signers``. The
    ``allow_unverified`` option verifies content integrity but deliberately
    skips that trust decision and is intended only for offline inspection.
    """

    info = parse_signed_object(data, expected_econtent_type=_ICAO_CSCA_MASTER_LIST_OID, label="Master List")
    verify_signed_object(info)
    if not allow_unverified:
        if not trusted_signers:
            raise CMSVerificationException("Master List Signer trust anchors are required")
        anchors = [load_certificate_der(bytes(x)) for x in trusted_signers]
        if bytes(info.dsc_der) not in {bytes(x) for x in anchors}:
            verify_chain(info.dsc_der, anchors)

    try:
        master_list, rest = der_decode(info.econtent, asn1Spec=CscaMasterList())
    except Exception as exc:
        raise CMSVerificationException("Master List payload is invalid: " + str(exc))
    if rest:
        raise CMSVerificationException("Master List payload has trailing data")
    if int(master_list["version"]) != 0:
        raise CMSVerificationException("Unsupported Master List version: " + str(int(master_list["version"])))

    certs = [entry.asOctets() for entry in master_list["certList"]]
    if not certs:
        raise CMSVerificationException("Master List contains no CSCA certificates")
    return certs


# --- X.509 ------------------------------------------------------------------


def load_certificates(data):
    """Return a list of DER certificates from PEM or DER input.

    PEM is parsed strictly: only the base64 between ``-----BEGIN CERTIFICATE-----``
    and ``-----END CERTIFICATE-----`` is decoded, so descriptive text that PKI
    distributions wrap around the block (e.g. an ``openssl x509 -text`` dump) is
    ignored instead of corrupting the data. A file may hold several certificates
    (a bundle); all are returned.
    """
    if b"-----BEGIN" in data:
        return _pem_certificates(data)
    return [bytes(data)]


def _pem_certificates(data):
    text = data.decode("ascii", errors="ignore")
    certs: list[bytes] = []
    collecting = False
    chunk: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if "-----BEGIN CERTIFICATE-----" in stripped:
            collecting = True
            chunk = []
        elif "-----END CERTIFICATE-----" in stripped:
            collecting = False
            try:
                certs.append(base64.b64decode("".join(chunk)))
            except (ValueError, TypeError):
                pass
        elif collecting:
            chunk.append(stripped)
    return certs


def load_certificate_der(data):
    """Return the DER bytes of the first certificate in DER or PEM input.

    @raise CMSVerificationException: If no certificate can be extracted.
    """
    certs = load_certificates(data)
    if not certs:
        raise CMSVerificationException("No certificate found in input")
    return certs[0]


def is_certificate(der):
    """Return True if ``der`` decodes as an X.509 certificate."""
    try:
        _parse_certificate(der)
    except CMSVerificationException:
        return False
    return True


def certificate_to_pem(der):
    """Encode a DER certificate as PEM bytes (no OpenSSL)."""
    b64 = base64.b64encode(der).decode("ascii")
    lines = "\n".join(textwrap.wrap(b64, 64))
    return ("-----BEGIN CERTIFICATE-----\n" + lines + "\n-----END CERTIFICATE-----\n").encode("ascii")


def certificate_serial(der):
    """Return the certificate serial number as an int."""
    return int(_parse_certificate(der)["tbsCertificate"]["serialNumber"])


def certificate_sha1_fingerprint(der):
    """Return the SHA-1 fingerprint of the DER certificate as ``AA:BB:...``."""
    digest = SHA1.new(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def certificate_sha256_fingerprint(der):
    """Return the SHA-256 fingerprint of the DER certificate as ``AA:BB:...``."""
    digest = SHA256.new(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


_DN_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}


def _name_to_dict(name):
    attrs = {}
    for rdn in name["rdnSequence"]:
        for atv in rdn:
            oid = str(atv["type"])
            try:
                decoded, _ = der_decode(atv["value"].asOctets())
                value = str(decoded)
            except Exception:
                value = atv["value"].asOctets().hex().upper()
            attrs[_DN_OID_NAMES.get(oid, oid)] = value
    return attrs


def certificate_summary(der):
    """Return JSON-friendly identifying information for an X.509 certificate."""
    cert = _parse_certificate(der)
    tbs = cert["tbsCertificate"]
    not_before = _time_to_datetime(tbs["validity"]["notBefore"])
    not_after = _time_to_datetime(tbs["validity"]["notAfter"])

    from pypassport.doc9303.security_info import describe_spki_from_der

    signature_oid = str(cert["signatureAlgorithm"]["algorithm"])
    try:
        public_key = describe_spki_from_der(_spki_der(cert))
    except Exception:
        public_key = {"spki_der_hex": _spki_der(cert).hex().upper()}

    return {
        "subject": _name_to_dict(tbs["subject"]),
        "issuer": _name_to_dict(tbs["issuer"]),
        "serial_number": format(int(tbs["serialNumber"]), "X"),
        "not_before": not_before.isoformat() if not_before is not None else None,
        "not_after": not_after.isoformat() if not_after is not None else None,
        "signature_algorithm_oid": signature_oid,
        "signature_algorithm": OID.get(signature_oid, signature_oid),
        "sha1_fingerprint": certificate_sha1_fingerprint(der),
        "sha256_fingerprint": certificate_sha256_fingerprint(der),
        "public_key": public_key,
    }


def public_key_to_pem(spki_der):
    """Return a PEM SubjectPublicKeyInfo for a DER public key (RSA or EC)."""
    try:
        key: Any = RSA.import_key(spki_der)
    except (ValueError, IndexError, TypeError):
        key = ECC.import_key(spki_der)
    pem = key.export_key(format="PEM")
    return pem.encode("ascii") if isinstance(pem, str) else pem


def verify_chain(dsc_der, csca_ders):
    """Verify that the DSC is signed by one of the trusted CSCA certificates.

    Replaces ``openssl verify -CApath``: locates the CSCA whose subject matches
    the DSC issuer, verifies the DSC signature with the CSCA public key, and
    checks both certificates' validity periods.

    @param dsc_der: The Document Signer certificate (DER).
    @param csca_ders: An iterable of trusted CSCA certificates (DER).
    @return: True if a valid chain is found.
    @raise CMSVerificationException: If no trusted issuer validates the DSC.
    """
    verify_chain_with_issuer(dsc_der, csca_ders)
    return True


def verify_chain_with_issuer(dsc_der, csca_ders):
    """Verify a DSC chain and return the trusted CSCA certificate DER used."""
    dsc = _parse_certificate(dsc_der)
    dsc_tbs = dsc["tbsCertificate"]
    issuer = der_encode(dsc_tbs["issuer"])

    candidates = []
    for csca_der in csca_ders:
        try:
            csca = _parse_certificate(csca_der)
        except CMSVerificationException:
            # A non-certificate file in the trust store must not abort the whole
            # verification — skip it and try the rest.
            continue
        if der_encode(csca["tbsCertificate"]["subject"]) == issuer:
            candidates.append((bytes(csca_der), csca))
    if not candidates:
        raise CMSVerificationException("No CSCA matches the Document Signer issuer")

    _check_validity(dsc_tbs)

    last_error = None
    for csca_der, csca in candidates:
        try:
            _check_validity(csca["tbsCertificate"])
            _verify_signature(
                _spki_der(csca),
                str(dsc["signatureAlgorithm"]["algorithm"]),
                dsc["signature"].asOctets(),
                der_encode(dsc_tbs),
                signature_parameters=(dsc["signatureAlgorithm"]["parameters"].asOctets()
                                      if dsc["signatureAlgorithm"]["parameters"].isValue else None),
            )
            return csca_der
        except CMSVerificationException as exc:
            last_error = exc
    raise CMSVerificationException("DSC signature not validated by any trusted CSCA: " + str(last_error))


def _check_validity(tbs, *, when=None):
    validity = tbs["validity"]
    not_before = _time_to_datetime(validity["notBefore"])
    not_after = _time_to_datetime(validity["notAfter"])
    now = when or datetime.now(timezone.utc)
    if not_before is not None and now < not_before:
        raise CMSVerificationException("Certificate is not yet valid")
    if not_after is not None and now > not_after:
        raise CMSVerificationException("Certificate has expired")


def _time_to_datetime(time_choice):
    component = time_choice.getComponent()
    try:
        dt = component.asDateTime
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# --- Raw RSA (Active Authentication) ---------------------------------------


def rsa_recover(spki_der, signature):
    """Raw RSA public-key transform ``m = s^e mod n`` (no padding).

    Replaces ``openssl rsautl -raw -verify``: used by Active Authentication and
    the sign-everything attack to recover the ISO 9796-2 message.

    @param spki_der: The RSA public key as a DER SubjectPublicKeyInfo (DG15 body).
    @param signature: The signature bytes returned by the chip.
    @return: The recovered message, left-padded to the modulus length.
    """
    key = RSA.import_key(spki_der)
    s = int.from_bytes(signature, "big")
    if len(signature) != key.size_in_bytes() or s >= key.n:
        raise CMSVerificationException("RSA signature representative is out of range")
    m = pow(s, key.e, key.n)
    size = (key.n.bit_length() + 7) // 8
    return m.to_bytes(size, "big")


# --- internal helpers -------------------------------------------------------


def _parse_certificate(der):
    try:
        cert, _ = der_decode(der, asn1Spec=rfc5280.Certificate())
    except PyAsn1Error:
        raise CMSVerificationException("Input is not a valid X.509 certificate")
    return cert


def _spki_der(cert):
    return der_encode(cert["tbsCertificate"]["subjectPublicKeyInfo"])


def _hash_for_oid(oid):
    hash_module = _HASH_BY_OID.get(oid)
    if hash_module is None:
        raise CMSVerificationException("Unsupported hash algorithm OID: " + str(oid))
    return hash_module


def _verify_signature(spki_der, sig_alg_oid, signature, message, digest_oid=None, signature_parameters=None):
    """Verify ``signature`` over ``message`` using the public key in ``spki_der``.

    Supports RSA PKCS#1 v1.5, RSA-PSS (best effort) and ECDSA.
    """
    if sig_alg_oid in _ECDSA_OIDS:
        _verify_ecdsa(spki_der, signature, message, _hash_for_oid(sig_alg_oid))
        return

    key = RSA.import_key(spki_der)

    if sig_alg_oid in _RSA_PKCS1_OIDS:
        hash_obj = _hash_for_oid(sig_alg_oid).new(message)
        verifier: Any = pkcs1_15.new(key)
    elif sig_alg_oid == _RSA_ENCRYPTION_OID:
        hash_obj = _hash_for_oid(digest_oid).new(message)
        verifier = pkcs1_15.new(key)
    elif sig_alg_oid == _RSA_PSS_OID:
        if signature_parameters is None:
            raise CMSVerificationException("RSA-PSS parameters are mandatory")
        params, rest = der_decode(signature_parameters, asn1Spec=rfc4055.RSASSA_PSS_params())
        if rest or der_encode(params) != signature_parameters:
            raise CMSVerificationException("Invalid/non-canonical RSA-PSS parameters")
        pss_digest_oid = str(params["hashAlgorithm"]["algorithm"])
        mgf = params["maskGenAlgorithm"]
        mgf_params, rest = der_decode(mgf["parameters"].asOctets(), asn1Spec=rfc5280.AlgorithmIdentifier())
        if (str(mgf["algorithm"]) != "1.2.840.113549.1.1.8" or rest
                or str(mgf_params["algorithm"]) != pss_digest_oid or int(params["trailerField"]) != 1):
            raise CMSVerificationException("Unsupported RSA-PSS hash/MGF/trailer combination")
        if digest_oid is not None and _hash_for_oid(digest_oid) is not _hash_for_oid(pss_digest_oid):
            raise CMSVerificationException("RSA-PSS parameters conflict with digestAlgorithm")
        hash_module = _hash_for_oid(pss_digest_oid)
        hash_obj = hash_module.new(message)
        verifier = pss.new(key, mask_func=lambda seed, length: pss.MGF1(seed, length, hash_module),
                           salt_bytes=int(params["saltLength"]))
    else:
        raise CMSVerificationException("Unsupported signature algorithm OID: " + str(sig_alg_oid))

    try:
        verifier.verify(hash_obj, signature)
    except (ValueError, TypeError) as exc:
        raise CMSVerificationException("RSA signature verification failed: " + str(exc))


def _verify_ecdsa(spki_der, signature, message, hash_module):
    """Verify a DER-encoded ECDSA ``signature`` over ``message``.

    pycryptodome is tried first (the fast path for NIST named curves). It cannot
    import Brainpool curves, nor EC keys that carry *explicit* domain parameters
    instead of a named-curve OID — both common in national DSC / CSCA
    certificates (e.g. Belgium). For those the ``ecdsa`` library is used, which
    handles every curve encoding the ICAO PKI emits.
    """
    try:
        key = ECC.import_key(spki_der)
    except (ValueError, IndexError, TypeError):
        # Covers "Not an ECC DER key" (explicit parameters) and
        # "Unsupported ECC curve" (Brainpool) — fall back below.
        key = None

    if key is not None:
        try:
            DSS.new(key, "fips-186-3", encoding="der").verify(hash_module.new(message), signature)
        except (ValueError, TypeError) as exc:
            raise CMSVerificationException("ECDSA signature verification failed: " + str(exc))
        return

    try:
        verifying_key = VerifyingKey.from_der(spki_der)
    except Exception as exc:
        raise CMSVerificationException("Unsupported EC public key: " + str(exc))
    digest = hash_module.new(message).digest()
    try:
        verifying_key.verify_digest(signature, digest, sigdecode=sigdecode_der, allow_truncate=True)
    except BadSignatureError as exc:
        raise CMSVerificationException("ECDSA signature verification failed: " + str(exc))
    except Exception as exc:
        raise CMSVerificationException("ECDSA signature verification error: " + str(exc))
