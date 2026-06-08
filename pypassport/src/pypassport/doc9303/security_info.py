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

from dataclasses import dataclass
from typing import List, Optional

from pyasn1.codec.der.decoder import decode as asn1decode


# Mapping of known PACE protocol OIDs (BSI TR-03110 part 3, A.1.1.2).
# The key is the dotted-string OID, the value is a tuple
# (key_agreement, mapping, cipher, key_size_bits).
_PACE_OID_TABLE = {
    # DH, Generic Mapping
    "0.4.0.127.0.7.2.2.4.1.1": ("DH",   "GM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.1.2": ("DH",   "GM", "AES",  128),
    "0.4.0.127.0.7.2.2.4.1.3": ("DH",   "GM", "AES",  192),
    "0.4.0.127.0.7.2.2.4.1.4": ("DH",   "GM", "AES",  256),
    # ECDH, Generic Mapping
    "0.4.0.127.0.7.2.2.4.2.1": ("ECDH", "GM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.2.2": ("ECDH", "GM", "AES",  128),
    "0.4.0.127.0.7.2.2.4.2.3": ("ECDH", "GM", "AES",  192),
    "0.4.0.127.0.7.2.2.4.2.4": ("ECDH", "GM", "AES",  256),
    # DH, Integrated Mapping
    "0.4.0.127.0.7.2.2.4.3.1": ("DH",   "IM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.3.2": ("DH",   "IM", "AES",  128),
    "0.4.0.127.0.7.2.2.4.3.3": ("DH",   "IM", "AES",  192),
    "0.4.0.127.0.7.2.2.4.3.4": ("DH",   "IM", "AES",  256),
    # ECDH, Integrated Mapping
    "0.4.0.127.0.7.2.2.4.4.1": ("ECDH", "IM", "3DES", 112),
    "0.4.0.127.0.7.2.2.4.4.2": ("ECDH", "IM", "AES",  128),
    "0.4.0.127.0.7.2.2.4.4.3": ("ECDH", "IM", "AES",  192),
    "0.4.0.127.0.7.2.2.4.4.4": ("ECDH", "IM", "AES",  256),
    # ECDH, Chip Authentication Mapping
    "0.4.0.127.0.7.2.2.4.6.2": ("ECDH", "CAM", "AES", 128),
    "0.4.0.127.0.7.2.2.4.6.3": ("ECDH", "CAM", "AES", 192),
    "0.4.0.127.0.7.2.2.4.6.4": ("ECDH", "CAM", "AES", 256),
}


# Default-supported variants for the negotiator. The order defines
# preference: stronger AES variants come first, then 3DES, GM before IM.
# Only OIDs the codebase has any chance of running are listed here.
_DEFAULT_SUPPORTED = (
    "0.4.0.127.0.7.2.2.4.2.4",  # ECDH-GM-AES-256
    "0.4.0.127.0.7.2.2.4.2.3",  # ECDH-GM-AES-192
    "0.4.0.127.0.7.2.2.4.2.2",  # ECDH-GM-AES-128
    "0.4.0.127.0.7.2.2.4.1.4",  # DH-GM-AES-256
    "0.4.0.127.0.7.2.2.4.1.3",  # DH-GM-AES-192
    "0.4.0.127.0.7.2.2.4.1.2",  # DH-GM-AES-128
    "0.4.0.127.0.7.2.2.4.2.1",  # ECDH-GM-3DES
    "0.4.0.127.0.7.2.2.4.1.1",  # DH-GM-3DES
)


class SecurityInfoParseError(Exception):
    """Raised when the SecurityInfos blob cannot be DER-decoded."""


@dataclass(frozen=True)
class PACEInfo:
    """A single PACEInfo entry extracted from SecurityInfos."""

    oid: str
    version: int
    parameter_id: Optional[int] = None

    @property
    def key_agreement(self) -> Optional[str]:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[0] if entry else None

    @property
    def mapping(self) -> Optional[str]:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[1] if entry else None

    @property
    def cipher(self) -> Optional[str]:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[2] if entry else None

    @property
    def key_size(self) -> Optional[int]:
        entry = _PACE_OID_TABLE.get(self.oid)
        return entry[3] if entry else None

    def is_known(self) -> bool:
        return self.oid in _PACE_OID_TABLE


class SecurityInfoParser:
    """
    Parses an EF.CardAccess / DG14 SecurityInfos blob and exposes the
    PACEInfo entries it contains.
    """

    # Prefix matching the id-PACE arc (0.4.0.127.0.7.2.2.4) — anything
    # whose OID starts with this is a PACEInfo.
    _PACE_OID_PREFIX = "0.4.0.127.0.7.2.2.4."

    def __init__(self, supported_oids=None):
        """
        :param supported_oids: Iterable of OID strings that the local stack
            can actually run. If None, a built-in default list is used.
        """
        self._supported = tuple(supported_oids) if supported_oids is not None else _DEFAULT_SUPPORTED

    def parse(self, data: bytes) -> List[PACEInfo]:
        """
        Decode SecurityInfos and return every PACEInfo entry found.

        :raise SecurityInfoParseError: If the input cannot be DER-decoded.
        """
        if not data:
            raise SecurityInfoParseError("Empty SecurityInfos blob")

        try:
            decoded, _ = asn1decode(data)
        except Exception as exc:
            raise SecurityInfoParseError(f"DER decoding failed: {exc}") from exc

        infos: List[PACEInfo] = []
        for seq in decoded:
            try:
                oid_str = str(seq[0])
            except Exception:
                continue
            if not oid_str.startswith(self._PACE_OID_PREFIX):
                continue
            try:
                version = int(seq[1])
            except Exception:
                continue
            parameter_id: Optional[int] = None
            if len(seq) > 2:
                try:
                    parameter_id = int(seq[2])
                except Exception:
                    parameter_id = None
            infos.append(PACEInfo(oid=oid_str, version=version, parameter_id=parameter_id))
        return infos

    def select_supported(self, infos: List[PACEInfo]) -> Optional[PACEInfo]:
        """
        Return the first PACEInfo whose OID appears in the supported list,
        following the supported-OID preference order. Returns None if none
        match.
        """
        by_oid = {info.oid: info for info in infos}
        for oid in self._supported:
            if oid in by_oid:
                return by_oid[oid]
        return None
