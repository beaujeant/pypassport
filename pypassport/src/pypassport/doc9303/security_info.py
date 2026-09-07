"""
Parser for ICAO 9303 / BSI TR-03110 SecurityInfos (EF.CardAccess, DG14).

SecurityInfos ::= SET OF SecurityInfo
SecurityInfo  ::= SEQUENCE {
    protocol      OBJECT IDENTIFIER,
    requiredData  ANY DEFINED BY protocol,
    optionalData  ANY DEFINED BY protocol OPTIONAL
}
PACEInfo ::= SEQUENCE {
    protocol     OBJECT IDENTIFIER,
    version      INTEGER,                  -- SHOULD be 2
    parameterId  INTEGER OPTIONAL
}

This module is used to detect whether a chip advertises PACE and, if so,
which variants are supported. It does not perform any APDU exchange.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pyasn1.codec.der.decoder import decode as asn1decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.asn1 import to_asn1_length
from pypassport.der_object_identifier import OID
from pypassport.doc9303.domain_parameters import resolve as resolve_domain_parameters
from pypassport.utils import parse_tlv

# Mapping of known PACE protocol OIDs (BSI TR-03110 part 3, A.1.1.2).
# The key is the dotted-string OID, the value is a tuple
# (key_agreement, mapping, cipher, key_size_bits).
_PACE_OID_TABLE: dict[str, tuple[str, str, str, int]] = {
    # DH, Generic Mapping
    "0.4.0.127.0.7.2.2.4.1.1": ("DH", "GM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.1.2": ("DH", "GM", "AES", 128),
    "0.4.0.127.0.7.2.2.4.1.3": ("DH", "GM", "AES", 192),
    "0.4.0.127.0.7.2.2.4.1.4": ("DH", "GM", "AES", 256),
    # ECDH, Generic Mapping
    "0.4.0.127.0.7.2.2.4.2.1": ("ECDH", "GM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.2.2": ("ECDH", "GM", "AES", 128),
    "0.4.0.127.0.7.2.2.4.2.3": ("ECDH", "GM", "AES", 192),
    "0.4.0.127.0.7.2.2.4.2.4": ("ECDH", "GM", "AES", 256),
    # DH, Integrated Mapping
    "0.4.0.127.0.7.2.2.4.3.1": ("DH", "IM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.3.2": ("DH", "IM", "AES", 128),
    "0.4.0.127.0.7.2.2.4.3.3": ("DH", "IM", "AES", 192),
    "0.4.0.127.0.7.2.2.4.3.4": ("DH", "IM", "AES", 256),
    # ECDH, Integrated Mapping
    "0.4.0.127.0.7.2.2.4.4.1": ("ECDH", "IM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.4.2": ("ECDH", "IM", "AES", 128),
    "0.4.0.127.0.7.2.2.4.4.3": ("ECDH", "IM", "AES", 192),
    "0.4.0.127.0.7.2.2.4.4.4": ("ECDH", "IM", "AES", 256),
    # ECDH, Chip Authentication Mapping
    "0.4.0.127.0.7.2.2.4.6.2": ("ECDH", "CAM", "AES", 128),
    "0.4.0.127.0.7.2.2.4.6.3": ("ECDH", "CAM", "AES", 192),
    "0.4.0.127.0.7.2.2.4.6.4": ("ECDH", "CAM", "AES", 256),
}
_PACE_DOMAIN_OIDS = {f"0.4.0.127.0.7.2.2.4.{value}" for value in (1, 2, 3, 4, 6)}


# Default-supported variants for the negotiator. The order defines
# preference: stronger AES variants come first, then 3DES, GM before IM.
# Only OIDs the codebase has any chance of running are listed here.
_DEFAULT_SUPPORTED: tuple[str, ...] = (
    "0.4.0.127.0.7.2.2.4.6.4",  # ECDH-CAM-AES-256
    "0.4.0.127.0.7.2.2.4.6.3",  # ECDH-CAM-AES-192
    "0.4.0.127.0.7.2.2.4.6.2",  # ECDH-CAM-AES-128
    "0.4.0.127.0.7.2.2.4.2.4",  # ECDH-GM-AES-256
    "0.4.0.127.0.7.2.2.4.2.3",  # ECDH-GM-AES-192
    "0.4.0.127.0.7.2.2.4.2.2",  # ECDH-GM-AES-128
    "0.4.0.127.0.7.2.2.4.1.4",  # DH-GM-AES-256
    "0.4.0.127.0.7.2.2.4.1.3",  # DH-GM-AES-192
    "0.4.0.127.0.7.2.2.4.1.2",  # DH-GM-AES-128
    "0.4.0.127.0.7.2.2.4.2.1",  # ECDH-GM-3DES
    "0.4.0.127.0.7.2.2.4.1.1",  # DH-GM-3DES
    "0.4.0.127.0.7.2.2.4.4.4",  # ECDH-IM-AES-256
    "0.4.0.127.0.7.2.2.4.4.3",  # ECDH-IM-AES-192
    "0.4.0.127.0.7.2.2.4.4.2",  # ECDH-IM-AES-128
    "0.4.0.127.0.7.2.2.4.3.4",  # DH-IM-AES-256
    "0.4.0.127.0.7.2.2.4.3.3",  # DH-IM-AES-192
    "0.4.0.127.0.7.2.2.4.3.2",  # DH-IM-AES-128
    "0.4.0.127.0.7.2.2.4.4.1",  # ECDH-IM-3DES
    "0.4.0.127.0.7.2.2.4.3.1",  # DH-IM-3DES
)


class SecurityInfoParseError(Exception):
    """Raised when the SecurityInfos blob cannot be DER-decoded."""


@dataclass(frozen=True)
class PACEInfo:
    """A single PACEInfo entry extracted from SecurityInfos."""

    oid: str
    version: int
    parameter_id: int | None = None
    domain_parameters: bytes | None = None

    @property
    def key_agreement(self) -> str | None:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[0] if entry else None

    @property
    def mapping(self) -> str | None:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[1] if entry else None

    @property
    def cipher(self) -> str | None:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[2] if entry else None

    @property
    def key_size(self) -> int | None:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[3] if entry else None

    def is_known(self) -> bool:
        return self.oid in _PACE_OID_TABLE

    def is_supported(self) -> bool:
        if not self.is_known() or self.version != 2:
            return False
        try:
            domain = resolve_domain_parameters(self.key_agreement, self.parameter_id, self.domain_parameters)
            if self.mapping == "IM":
                if self.key_agreement == "DH" and domain.q is None:
                    return False
                if self.key_agreement == "ECDH" and domain.curve.p() % 4 != 3:
                    return False
        except Exception:
            return False
        return True


class SecurityInfoParser:
    """
    Parses an EF.CardAccess / DG14 SecurityInfos blob and exposes the
    PACEInfo entries it contains.
    """

    # Prefix matching the id-PACE arc (0.4.0.127.0.7.2.2.4) — anything
    # whose OID starts with this is a PACEInfo.
    _PACE_OID_PREFIX = "0.4.0.127.0.7.2.2.4."

    def __init__(self, supported_oids: Iterable[str] | None = None):
        """
        :param supported_oids: Iterable of OID strings that the local stack
            can actually run. If None, a built-in default list is used.
        """
        self._supported: tuple[str, ...] = tuple(supported_oids) if supported_oids is not None else _DEFAULT_SUPPORTED

    def parse(self, data: bytes) -> list[PACEInfo]:
        """
        Decode SecurityInfos and return every PACEInfo entry found.

        :raise SecurityInfoParseError: If the input cannot be DER-decoded.
        """
        if not data:
            raise SecurityInfoParseError("Empty SecurityInfos blob")

        # Strip Application-class wrappers (some chips add one or more layers)
        while data and (data[0] & 0xC0) == 0x40:
            try:
                _, data, _ = parse_tlv(data)
            except Exception:
                break

        if not data:
            raise SecurityInfoParseError("Empty after unwrapping")

        # Strip the outer SET (0x31) or SEQUENCE (0x30) wrapper to get elements.
        # Some chips encode SecurityInfos as SEQUENCE instead of SET.
        if data[0] not in (0x30, 0x31):
            raise SecurityInfoParseError(f"DER decoding failed: expected SET or SEQUENCE, got tag 0x{data[0]:02X}")
        try:
            _, set_val, _ = parse_tlv(data)
        except Exception as exc:
            raise SecurityInfoParseError(f"DER decoding failed: {exc}") from exc

        # Walk SET elements one by one so that non-SEQUENCE elements (e.g.
        # Application-class tags some chips embed) are silently skipped rather
        # than aborting the entire decode.
        infos: list[PACEInfo] = []
        domains = {}
        pos = 0
        while pos < len(set_val):
            try:
                tag, elem_val, consumed = parse_tlv(set_val[pos:])
            except Exception:
                break
            pos += consumed

            if tag != "30":
                continue

            # Reconstruct the SEQUENCE TLV and let pyasn1 decode it
            seq_der = b"\x30" + to_asn1_length(len(elem_val)) + elem_val

            try:
                seq, _ = asn1decode(seq_der)
                oid_str = str(seq[0])
            except Exception:
                continue

            if not oid_str.startswith(self._PACE_OID_PREFIX):
                continue

            if oid_str in _PACE_DOMAIN_OIDS:
                # PACEDomainParameterInfo has a base protocol OID, an
                # AlgorithmIdentifier, and a reference used by PACEInfo.
                try:
                    if len(seq) >= 3:
                        domains[int(seq[2])] = der_encode(seq[1][1])
                except Exception:
                    pass
                continue

            try:
                version = int(seq[1])
            except Exception:
                continue

            parameter_id: int | None = None
            if len(seq) > 2:
                try:
                    parameter_id = int(seq[2])
                except Exception:
                    pass

            infos.append(PACEInfo(oid=oid_str, version=version, parameter_id=parameter_id))

        return [PACEInfo(x.oid, x.version, x.parameter_id, domains.get(x.parameter_id)) for x in infos]

    def select_supported(self, infos: list[PACEInfo]) -> PACEInfo | None:
        """
        Return the first PACEInfo whose OID appears in the supported list,
        following the supported-OID preference order. Returns None if none
        match.
        """
        candidates = self.select_all_supported(infos)
        return candidates[0] if candidates else None

    def select_all_supported(self, infos):
        """Return every executable profile in preference order."""
        return [info for oid in self._supported for info in infos if info.oid == oid and info.is_supported()]


# ---------------------------------------------------------------------------
# Full SecurityInfos parsing (DG14)
# ---------------------------------------------------------------------------
#
# DG14 carries the complete SecurityInfos SET, which — unlike EF.CardAccess —
# usually contains Chip Authentication entries rather than PACE entries. The
# PACE-only SecurityInfoParser above is kept for access-control negotiation;
# parse_security_infos() below decodes *every* SecurityInfo type into a
# human-readable dict so DG14 exposes structured content instead of raw bytes.

# BSI TR-03110 / ICAO 9303 protocol OID arcs.
_ID_PK = "0.4.0.127.0.7.2.2.1"  # ChipAuthenticationPublicKeyInfo
_ID_TA = "0.4.0.127.0.7.2.2.2"  # TerminalAuthenticationInfo
_ID_CA = "0.4.0.127.0.7.2.2.3"  # ChipAuthenticationInfo
_ID_PACE = "0.4.0.127.0.7.2.2.4"  # PACEInfo / PACEDomainParameterInfo
_ID_AA = "2.23.136.1.1.5"  # ActiveAuthenticationInfo

_OID_RSA = "1.2.840.113549.1.1.1"
_OID_EC = "1.2.840.10045.2.1"

# Human-readable names for the protocol OIDs that may appear in DG14.
_PROTOCOL_OID_NAMES = {
    "0.4.0.127.0.7.2.2.1.1": "id-PK-DH",
    "0.4.0.127.0.7.2.2.1.2": "id-PK-ECDH",
    "0.4.0.127.0.7.2.2.2": "id-TA",
    "0.4.0.127.0.7.2.2.3.1.1": "id-CA-DH-3DES-CBC-CBC",
    "0.4.0.127.0.7.2.2.3.1.2": "id-CA-DH-AES-CBC-CMAC-128",
    "0.4.0.127.0.7.2.2.3.1.3": "id-CA-DH-AES-CBC-CMAC-192",
    "0.4.0.127.0.7.2.2.3.1.4": "id-CA-DH-AES-CBC-CMAC-256",
    "0.4.0.127.0.7.2.2.3.2.1": "id-CA-ECDH-3DES-CBC-CBC",
    "0.4.0.127.0.7.2.2.3.2.2": "id-CA-ECDH-AES-CBC-CMAC-128",
    "0.4.0.127.0.7.2.2.3.2.3": "id-CA-ECDH-AES-CBC-CMAC-192",
    "0.4.0.127.0.7.2.2.3.2.4": "id-CA-ECDH-AES-CBC-CMAC-256",
    "2.23.136.1.1.5": "id-icao-mrtd-security-aaProtocolObject",
    # PACEDomainParameterInfo OIDs (no key-size suffix).
    "0.4.0.127.0.7.2.2.4.1": "id-PACE-DH-GM",
    "0.4.0.127.0.7.2.2.4.2": "id-PACE-ECDH-GM",
    "0.4.0.127.0.7.2.2.4.3": "id-PACE-DH-IM",
    "0.4.0.127.0.7.2.2.4.4": "id-PACE-ECDH-IM",
    "0.4.0.127.0.7.2.2.4.6": "id-PACE-ECDH-CAM",
}

_PUBLIC_KEY_OID_NAMES = {
    _OID_RSA: "rsaEncryption",
    _OID_EC: "ecPublicKey",
    "1.2.840.10040.4.1": "dsa",
}

_EC_CURVE_OID_NAMES = {
    "1.2.840.10045.3.1.7": "prime256v1 (NIST P-256)",
    "1.3.132.0.34": "secp384r1 (NIST P-384)",
    "1.3.132.0.35": "secp521r1 (NIST P-521)",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
}

SecurityInfoDict = dict[str, object]


def security_info_name(oid: str) -> str:
    """Return a human-readable name for a SecurityInfo protocol OID."""
    if oid in _PROTOCOL_OID_NAMES:
        return _PROTOCOL_OID_NAMES[oid]
    entry = _PACE_OID_TABLE.get(oid)
    if entry:
        key_agreement, mapping, cipher, key_size = entry
        return f"id-PACE-{key_agreement}-{mapping}-{cipher}-{key_size}"
    return oid


def _decode_oid_bytes(value: bytes) -> str:
    """Decode raw OBJECT IDENTIFIER value bytes (no tag/length) to a dotted string."""
    if not value:
        return ""
    result = [str(value[0] // 40), str(value[0] % 40)]
    acc = 0
    for b in value[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            result.append(str(acc))
            acc = 0
    return ".".join(result)


def _read_optional_int(data: bytes) -> int | None:
    """Return the leading INTEGER value of *data*, or None if absent/non-integer."""
    if not data:
        return None
    try:
        tag, value, _ = parse_tlv(data)
    except Exception:
        return None
    if tag != "02":
        return None
    return int.from_bytes(value, "big")


def describe_spki_from_der(der: bytes) -> SecurityInfoDict:
    """
    Decode a DER SubjectPublicKeyInfo into a structured dict.

    Handles RSA (modulus / public exponent) and EC (named curve / public
    point) public keys; other algorithms expose the algorithm OID and the
    raw subjectPublicKey bit length only.

    :raise Exception: If *der* is not a decodable SubjectPublicKeyInfo.
    """
    spki, trailing = asn1decode(der)
    if trailing:
        raise SecurityInfoParseError("SubjectPublicKeyInfo has trailing DER data")
    algorithm = spki[0]
    algo_oid = str(algorithm[0])

    out: SecurityInfoDict = {
        "algorithm_oid": algo_oid,
        "algorithm": _PUBLIC_KEY_OID_NAMES.get(algo_oid, OID.get(algo_oid, algo_oid)),
        "spki_der_hex": der.hex().upper(),
    }

    public_key = spki[1]
    out["key_length_bits"] = len(public_key)
    try:
        key_bytes = public_key.asOctets()
    except Exception:
        key_bytes = b""
    out["subject_public_key_hex"] = key_bytes.hex().upper()

    if algo_oid == _OID_RSA:
        try:
            rsa_key, _ = asn1decode(key_bytes)
            modulus = int(rsa_key[0])
            exponent = int(rsa_key[1])
            out["modulus_bits"] = modulus.bit_length()
            out["public_exponent"] = exponent
            out["modulus"] = format(modulus, "X")
        except Exception:
            pass
    elif algo_oid == _OID_EC:
        if len(algorithm) > 1 and isinstance(algorithm[1], univ.ObjectIdentifier):
            curve_oid = str(algorithm[1])
            out["curve_oid"] = curve_oid
            out["curve"] = _EC_CURVE_OID_NAMES.get(curve_oid, curve_oid)
        elif len(algorithm) > 1:
            try:
                out["algorithm_parameters_der_hex"] = algorithm[1].asOctets().hex().upper()
            except Exception:
                pass
        if key_bytes:
            out["public_point"] = key_bytes.hex().upper()

    return out


def _describe_security_info(seq_val: bytes) -> SecurityInfoDict:
    """Decode one SecurityInfo SEQUENCE value into a structured dict."""
    tag, oid_bytes, oid_consumed = parse_tlv(seq_val)
    if tag != "06":
        raise SecurityInfoParseError("SecurityInfo does not start with an OID")
    oid = _decode_oid_bytes(oid_bytes)
    info: SecurityInfoDict = {"protocol_oid": oid, "protocol": security_info_name(oid)}
    rest = seq_val[oid_consumed:]
    if rest:
        _, _, required_consumed = parse_tlv(rest)
        info["required_data_der_hex"] = rest[:required_consumed].hex().upper()
        optional = rest[required_consumed:]
        if optional:
            info["optional_data_der_hex"] = optional.hex().upper()

    if oid.startswith(_ID_PK):
        # ChipAuthenticationPublicKeyInfo: SubjectPublicKeyInfo, keyId OPTIONAL
        _, _, spki_consumed = parse_tlv(rest)
        spki_der = rest[:spki_consumed]
        try:
            info["public_key"] = describe_spki_from_der(spki_der)
        except Exception:
            info["public_key_raw"] = spki_der.hex().upper()
        key_id = _read_optional_int(rest[spki_consumed:])
        if key_id is not None:
            info["key_id"] = key_id
    elif oid.startswith(_ID_CA):
        # ChipAuthenticationInfo: version INTEGER, keyId INTEGER OPTIONAL
        version_tag, version_val, version_consumed = parse_tlv(rest)
        if version_tag == "02":
            info["version"] = int.from_bytes(version_val, "big")
        key_id = _read_optional_int(rest[version_consumed:])
        if key_id is not None:
            info["key_id"] = key_id
    elif oid == _ID_AA:
        # ActiveAuthenticationInfo: version INTEGER, signatureAlgorithm OID OPTIONAL
        version_tag, version_val, version_consumed = parse_tlv(rest)
        if version_tag == "02":
            info["version"] = int.from_bytes(version_val, "big")
        tail = rest[version_consumed:]
        if tail:
            t, v, _ = parse_tlv(tail)
            if t == "06":
                sig_oid = _decode_oid_bytes(v)
                info["signature_algorithm_oid"] = sig_oid
                info["signature_algorithm"] = OID.get(sig_oid, sig_oid)
    elif oid.startswith(_ID_TA):
        # TerminalAuthenticationInfo: version INTEGER, efCVCA FileID OPTIONAL.
        version = _read_optional_int(rest)
        if version is not None:
            info["version"] = version
            _, _, version_consumed = parse_tlv(rest)
            optional = rest[version_consumed:]
            if optional:
                info["ef_cvca_der_hex"] = optional.hex().upper()
                try:
                    seq, trailing = asn1decode(optional)
                    if not trailing and len(seq):
                        try:
                            info["ef_cvca_fid"] = seq[0].asOctets().hex().upper()
                        except Exception:
                            info["ef_cvca_fid"] = f"{int(seq[0]):04X}"
                        if len(seq) > 1:
                            info["ef_cvca_sfi"] = int(seq[1])
                except Exception:
                    pass
    elif oid.startswith(_ID_PACE):
        if rest:
            t, v, consumed = parse_tlv(rest)
            if t == "02":  # PACEInfo: version INTEGER, parameterId INTEGER OPTIONAL
                info["version"] = int.from_bytes(v, "big")
                parameter_id = _read_optional_int(rest[consumed:])
                if parameter_id is not None:
                    info["parameter_id"] = parameter_id
            elif t == "30":  # PACEDomainParameterInfo: AlgorithmIdentifier, parameterId OPTIONAL
                dt, dv, _ = parse_tlv(v)
                if dt == "06":
                    dom_oid = _decode_oid_bytes(dv)
                    info["domain_parameter_oid"] = dom_oid
                    info["domain_parameter"] = security_info_name(dom_oid)
                parameter_id = _read_optional_int(rest[consumed:])
                if parameter_id is not None:
                    info["parameter_id"] = parameter_id

    return info


def parse_security_infos(data: bytes) -> list[SecurityInfoDict]:
    """
    Decode a SecurityInfos SET (e.g. DG14) into a list of structured dicts,
    one per SecurityInfo, covering Chip Authentication, Terminal
    Authentication, Active Authentication and PACE entries.

    :raise SecurityInfoParseError: If the blob cannot be DER-decoded.
    """
    if not data:
        raise SecurityInfoParseError("Empty SecurityInfos blob")

    # Strip Application-class wrappers (some chips add one or more layers).
    while data and (data[0] & 0xC0) == 0x40:
        try:
            _, data, _ = parse_tlv(data)
        except Exception:
            break

    if not data or data[0] not in (0x30, 0x31):
        got = f"0x{data[0]:02X}" if data else "empty input"
        raise SecurityInfoParseError(f"expected SET or SEQUENCE, got {got}")

    try:
        _, set_val, _ = parse_tlv(data)
    except Exception as exc:
        raise SecurityInfoParseError(f"DER decoding failed: {exc}") from exc

    infos: list[SecurityInfoDict] = []
    pos = 0
    while pos < len(set_val):
        try:
            tag, elem_val, consumed = parse_tlv(set_val[pos:])
        except Exception as exc:
            infos.append(
                {
                    "parse_error": str(exc),
                    "unparsed_tail_hex": set_val[pos:].hex().upper(),
                }
            )
            break
        pos += consumed
        if tag != "30":
            infos.append(
                {
                    "unexpected_tag": tag,
                    "security_info_der_hex": set_val[pos - consumed : pos].hex().upper(),
                    "value_hex": elem_val.hex().upper(),
                }
            )
            continue
        try:
            info = _describe_security_info(elem_val)
            info["security_info_der_hex"] = set_val[pos - consumed : pos].hex().upper()
            infos.append(info)
        except Exception as exc:
            infos.append(
                {
                    "security_info_der_hex": set_val[pos - consumed : pos].hex().upper(),
                    "parse_error": str(exc),
                }
            )

    return infos
