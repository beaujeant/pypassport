"""Strict ICAO PKI path, revocation, Master List and Deviation List support."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ
from pyasn1_modules import rfc5280

from pypassport.doc9303 import cms

ID_ICAO_DEVIATION_LIST = "2.23.136.1.1.7"


@dataclass
class ValidationResult:
    trusted: bool
    chain: list[bytes]
    warnings: list[str] = field(default_factory=list)
    deviations: list[dict] = field(default_factory=list)


def _cert(der):
    cert, rest = der_decode(der, asn1Spec=rfc5280.Certificate())
    if rest or der_encode(cert) != bytes(der):
        raise cms.CMSVerificationException("Certificate is not canonical DER")
    if cert["signatureAlgorithm"] != cert["tbsCertificate"]["signature"]:
        raise cms.CMSVerificationException("Inner and outer certificate signature algorithms differ")
    return cert


def _extensions(cert):
    result = {}
    extensions = cert["tbsCertificate"]["extensions"]
    if extensions.isValue:
        for ext in extensions:
            oid = str(ext["extnID"])
            if oid in result:
                raise cms.CMSVerificationException(f"Duplicate X.509 extension {oid}")
            result[oid] = ext
    return result


def _key_identifier(cert):
    ext = _extensions(cert).get("2.5.29.14")
    if ext is None:
        return None
    value, rest = der_decode(ext["extnValue"].asOctets(), asn1Spec=univ.OctetString())
    return None if rest else value.asOctets()


def _authority_identifier(cert):
    ext = _extensions(cert).get("2.5.29.35")
    if ext is None:
        return None
    value, rest = der_decode(ext["extnValue"].asOctets(), asn1Spec=rfc5280.AuthorityKeyIdentifier())
    if rest or not value["keyIdentifier"].isValue:
        return None
    return value["keyIdentifier"].asOctets()


def _self_issued(der):
    cert = _cert(der)
    return der_encode(cert["tbsCertificate"]["subject"]) == der_encode(cert["tbsCertificate"]["issuer"])


def _at(cert, role, when, *, allow_legacy):
    cms._check_validity(cert["tbsCertificate"], when=when)
    exts = _extensions(cert)
    known_critical = {"2.5.29.14", "2.5.29.35", "2.5.29.19", "2.5.29.15", "2.5.29.31", "2.5.29.32", "2.5.29.37"}
    unknown_critical = [oid for oid, ext in exts.items() if ext["critical"] and oid not in known_critical]
    if unknown_critical:
        raise cms.CMSVerificationException(f"Unprocessed critical X.509 extensions: {unknown_critical}")
    bc = exts.get("2.5.29.19")
    ku = exts.get("2.5.29.15")
    ca = None
    usages = None
    if bc:
        ca_value, rest = der_decode(bc["extnValue"].asOctets(), asn1Spec=rfc5280.BasicConstraints())
        ca = bool(ca_value["cA"]) if not rest and ca_value["cA"].isValue else False
    if ku:
        ku_value, rest = der_decode(ku["extnValue"].asOctets(), asn1Spec=rfc5280.KeyUsage())
        usages = ku_value if not rest else None
    if allow_legacy and ca is None and usages is None:
        return [f"Legacy {role} certificate has no BasicConstraints/KeyUsage"]
    if ca != (role in ("CSCA", "LINK")):
        raise cms.CMSVerificationException(f"{role} certificate BasicConstraints role mismatch")
    if usages is not None:
        required_bit = 5 if role in ("CSCA", "LINK") else 0
        if len(usages) <= required_bit or not usages[required_bit]:
            raise cms.CMSVerificationException(f"{role} certificate lacks required KeyUsage")
    return []


class TrustStore:
    """An explicitly anchored trust graph with CRLs and signed deviations."""

    def __init__(self, anchors=(), *, intermediates=(), crls=(), deviation_lists=(), allow_legacy_profiles=False):
        self.anchors = tuple(dict.fromkeys(cms.load_certificate_der(bytes(x)) for x in anchors))
        self.intermediates = tuple(dict.fromkeys(cms.load_certificate_der(bytes(x)) for x in intermediates))
        self.crls = tuple(bytes(x) for x in crls)
        self.deviation_lists = tuple(deviation_lists)
        self.allow_legacy_profiles = allow_legacy_profiles

    @classmethod
    def from_directory(cls, directory, *, master_list_signers=(), deviation_list_signers=(),
                       allow_legacy_profiles=False):
        """Ingest explicit CSCA anchors, authenticated Master Lists, CRLs and DLs."""
        anchors, intermediates, crls, deviations = [], [], [], []
        for path in sorted(Path(directory).expanduser().iterdir()):
            if not path.is_file():
                continue
            raw, ext = path.read_bytes(), path.suffix.lower()
            if ext == ".ml":
                loaded = cms.load_master_list_certificates(raw, master_list_signers)
                anchors.extend(x for x in loaded if _self_issued(x))
                intermediates.extend(x for x in loaded if not _self_issued(x))
            elif ext in (".crl", ".pemcrl"):
                crls.append(raw)
            elif ext in (".dl", ".deviation"):
                deviations.append(verify_deviation_list(raw, deviation_list_signers))
            elif ext in (".cer", ".crt", ".der", ".pem"):
                loaded = cms.load_certificates(raw)
                anchors.extend(x for x in loaded if _self_issued(x))
                intermediates.extend(x for x in loaded if not _self_issued(x))
        return cls(anchors, intermediates=intermediates, crls=crls, deviation_lists=deviations,
                   allow_legacy_profiles=allow_legacy_profiles)

    def verify_document_signer(self, dsc_der, *, at_time=None):
        when = at_time or datetime.now(timezone.utc)
        leaf_der = cms.load_certificate_der(bytes(dsc_der))
        leaf = _cert(leaf_der)
        warnings = _at(leaf, "DSC", when, allow_legacy=self.allow_legacy_profiles)
        anchors = set(self.anchors)
        candidates = {der: _cert(der) for der in (*self.anchors, *self.intermediates)}

        def walk(child_der, child, used):
            issuer_name = der_encode(child["tbsCertificate"]["issuer"])
            aki = _authority_identifier(child)
            for parent_der, parent in candidates.items():
                if parent_der in used or der_encode(parent["tbsCertificate"]["subject"]) != issuer_name:
                    continue
                if aki is not None and _key_identifier(parent) not in (None, aki):
                    continue
                try:
                    cms._verify_signature(
                        cms._spki_der(parent), str(child["signatureAlgorithm"]["algorithm"]),
                        child["signature"].asOctets(), der_encode(child["tbsCertificate"]),
                        signature_parameters=(child["signatureAlgorithm"]["parameters"].asOctets()
                                              if child["signatureAlgorithm"]["parameters"].isValue else None),
                    )
                    role = "CSCA" if parent_der in anchors else "LINK"
                    warnings.extend(_at(parent, role, when, allow_legacy=self.allow_legacy_profiles))
                    self._check_crls(parent_der, parent, child_der, child, when)
                except cms.CMSVerificationException:
                    continue
                if parent_der in anchors:
                    return [child_der, parent_der]
                tail = walk(parent_der, parent, used | {parent_der})
                if tail:
                    return [child_der] + tail
            return None

        chain = walk(leaf_der, leaf, {leaf_der})
        if chain is None:
            raise cms.CMSVerificationException("No ICAO certificate path reaches an explicit trust anchor")
        return ValidationResult(True, chain, warnings, list(self.deviation_lists))

    def _check_crls(self, issuer_der, issuer, child_der, child, when):
        serial = int(child["tbsCertificate"]["serialNumber"])
        issuer_name = der_encode(issuer["tbsCertificate"]["subject"])
        for crl_der in self.crls:
            try:
                crl, rest = der_decode(crl_der, asn1Spec=rfc5280.CertificateList())
                if rest or der_encode(crl) != crl_der:
                    continue
                if crl["signatureAlgorithm"] != crl["tbsCertList"]["signature"]:
                    raise cms.CMSVerificationException("CRL signature algorithms differ")
                tbs = crl["tbsCertList"]
                if der_encode(tbs["issuer"]) != issuer_name:
                    continue
                cms._verify_signature(cms._spki_der(issuer), str(crl["signatureAlgorithm"]["algorithm"]),
                                      crl["signature"].asOctets(), der_encode(tbs),
                                      signature_parameters=(crl["signatureAlgorithm"]["parameters"].asOctets()
                                                            if crl["signatureAlgorithm"]["parameters"].isValue else None))
                this_update = cms._time_to_datetime(tbs["thisUpdate"])
                next_update = cms._time_to_datetime(tbs["nextUpdate"]) if tbs["nextUpdate"].isValue else None
                if this_update and when < this_update or next_update and when > next_update:
                    raise cms.CMSVerificationException("Applicable CRL is outside its validity interval")
                for revoked in tbs["revokedCertificates"]:
                    if int(revoked["userCertificate"]) == serial:
                        raise cms.CMSVerificationException("Certificate is revoked by an applicable CSCA CRL")
            except cms.CMSVerificationException:
                raise
            except Exception as exc:
                raise cms.CMSVerificationException(f"Invalid applicable CRL: {exc}") from exc


def verify_deviation_list(data, trusted_signers):
    """Verify a Deviation List before exposing its DER deviation records."""
    info = cms.parse_signed_object(data, expected_econtent_type=ID_ICAO_DEVIATION_LIST, label="Deviation List")
    cms.verify_signed_object(info)
    anchors = tuple(cms.load_certificate_der(bytes(x)) for x in trusted_signers)
    if info.dsc_der not in anchors:
        cms.verify_chain(info.dsc_der, anchors)
    payload, rest = der_decode(info.econtent)
    if rest:
        raise cms.CMSVerificationException("Deviation List payload has trailing data")
    return {"signer": cms.certificate_summary(info.dsc_der), "raw_der": info.econtent, "asn1": payload.prettyPrint()}
