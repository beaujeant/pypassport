"""ASN.1 helper types and length encoding/decoding utilities for pypassport."""

from pypassport.hex_utils import bin_to_hex, bin_to_hex_rep, hex_to_bin

from pyasn1.type.univ import (
    Integer,
    Sequence,
    SequenceOf,
    ObjectIdentifier,
    OctetString,
    BitString,
    Null,
    Any,
)
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.constraint import ValueSizeConstraint

ub_DataGroups = Integer(16)


class asn1Exception(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class LDSSecurityObjectVersion(Integer):
    namedValues = NamedValues(
        ("V0", 0),
        ("V1", 1),
    )


class DataGroupNumber(Integer):
    namedValues = NamedValues(
        ("dataGroup1", 1),
        ("dataGroup2", 2),
        ("dataGroup3", 3),
        ("dataGroup4", 4),
        ("dataGroup5", 5),
        ("dataGroup6", 6),
        ("dataGroup7", 7),
        ("dataGroup8", 8),
        ("dataGroup9", 9),
        ("dataGroup10", 10),
        ("dataGroup11", 11),
        ("dataGroup12", 12),
        ("dataGroup13", 13),
        ("dataGroup14", 14),
        ("dataGroup15", 15),
        ("dataGroup16", 16),
    )


class DataGroupHash(Sequence):
    componentType = NamedTypes(
        NamedType("dataGroupNumber", Integer()),
        NamedType("dataGroupHashValue", OctetString()),
    )


class DataGroupHashValues(SequenceOf):
    componentType = DataGroupHash()
    subtypeSpec = ValueSizeConstraint(2, ub_DataGroups)


class AlgorithmIdentifier(Sequence):
    componentType = NamedTypes(
        NamedType("algorithm", ObjectIdentifier()),
        OptionalNamedType("parameters", Null()),
    )


DigestAlgorithmIdentifier = AlgorithmIdentifier()


class LDSVersionInfo(Sequence):
    # Spec says VisibleString but chips often send PrintableString; use Any
    # so the schema accepts either encoding, then decode the value manually.
    componentType = NamedTypes(
        NamedType("ldsVersion", Any()),
        NamedType("unicodeVersion", Any()),
    )


class LDSSecurityObject(Sequence):
    componentType = NamedTypes(
        NamedType("version", LDSSecurityObjectVersion()),
        NamedType("hashAlgorithm", DigestAlgorithmIdentifier),
        NamedType("dataGroupHashValues", DataGroupHashValues()),
        OptionalNamedType("ldsVersionInfo", LDSVersionInfo()),
    )


class SubjectPublicKeyInfo(Sequence):
    componentType = NamedTypes(
        NamedType("algorithm", AlgorithmIdentifier()),
        NamedType("subjectPublicKey", BitString()),
    )


id_icao = ObjectIdentifier((2, 23, 136))
id_icao_mrtd = ObjectIdentifier(id_icao + (1,))
id_icao_mrtdsecurity = ObjectIdentifier(id_icao_mrtd + (1,))
id_icao_ldsSecurityObject = ObjectIdentifier(id_icao_mrtdsecurity + (1,))


def asn1_length(data: bytes) -> tuple:
    """Decode an ASN.1 length field and return (length, bytes_consumed).

    >>> asn1_length(b"\\x22")
    (34, 1)
    >>> asn1_length(b"\\x81\\xaa")
    (170, 2)
    >>> asn1_length(b"\\x82\\xaa\\xbb")
    (43707, 3)

    @param data: A length value encoded in ASN.1 format.
    @type data: bytes
    @return: A tuple (decoded_length, encoding_size).
    @raise asn1Exception: If the field does not follow ASN.1 notation.
    """
    if not data:
        raise asn1Exception("Truncated ASN.1 length")
    if data[0] <= 0x7F:
        return (bin_to_hex(data[0]), 1)
    width = data[0] & 0x7F
    if width == 0:
        raise asn1Exception("Indefinite ASN.1 lengths are not accepted")
    if width > 4 or len(data) < 1 + width:
        raise asn1Exception("Cannot decode the ASN.1 length from this field: " + bin_to_hex_rep(data))
    return (bin_to_hex(data[1:1 + width]), 1 + width)


def to_asn1_length(data: int) -> bytes:
    """Encode an integer as an ASN.1 length field.

    >>> bin_to_hex_rep(to_asn1_length(34))
    '22'
    >>> bin_to_hex_rep(to_asn1_length(170))
    '81aa'
    >>> bin_to_hex_rep(to_asn1_length(43707))
    '82aabb'

    @param data: The integer value to encode.
    @type data: int
    @return: The ASN.1 encoded length as bytes.
    @rtype: bytes
    @raise asn1Exception: If the value is out of range (must be 0 <= data <= 0xFFFF).
    """
    if data < 0:
        raise asn1Exception("ASN.1 length cannot be negative")
    if data <= 0x7F:
        return hex_to_bin(data)
    encoded = data.to_bytes((data.bit_length() + 7) // 8, "big")
    if len(encoded) > 4:
        raise asn1Exception("The value is too big, must be <= FFFFFFFF")
    return bytes([0x80 | len(encoded)]) + encoded
