"""ASN.1 helper types and length encoding/decoding utilities for pypassport."""

from pypassport.hex_utils import binToHex, binToHexRep, hexToBin, hexRepToBin

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
        ('V0', 0),
        ('V1', 1),
    )


class DataGroupNumber(Integer):
    namedValues = NamedValues(
        ('dataGroup1', 1),
        ('dataGroup2', 2),
        ('dataGroup3', 3),
        ('dataGroup4', 4),
        ('dataGroup5', 5),
        ('dataGroup6', 6),
        ('dataGroup7', 7),
        ('dataGroup8', 8),
        ('dataGroup9', 9),
        ('dataGroup10', 10),
        ('dataGroup11', 11),
        ('dataGroup12', 12),
        ('dataGroup13', 13),
        ('dataGroup14', 14),
        ('dataGroup15', 15),
        ('dataGroup16', 16),
    )


class DataGroupHash(Sequence):
    componentType = NamedTypes(
        NamedType('dataGroupNumber', Integer()),
        NamedType('dataGroupHashValue', OctetString()),
    )


class DataGroupHashValues(SequenceOf):
    componentType = DataGroupHash()
    subtypeSpec = ValueSizeConstraint(2, ub_DataGroups)


class AlgorithmIdentifier(Sequence):
    componentType = NamedTypes(
        NamedType('algorithm', ObjectIdentifier()),
        OptionalNamedType('parameters', Null()),
    )


DigestAlgorithmIdentifier = AlgorithmIdentifier()


class LDSVersionInfo(Sequence):
    # Spec says VisibleString but chips often send PrintableString; use Any
    # so the schema accepts either encoding, then decode the value manually.
    componentType = NamedTypes(
        NamedType('ldsVersion', Any()),
        NamedType('unicodeVersion', Any()),
    )


class LDSSecurityObject(Sequence):
    componentType = NamedTypes(
        NamedType('version', LDSSecurityObjectVersion()),
        NamedType('hashAlgorithm', DigestAlgorithmIdentifier),
        NamedType('dataGroupHashValues', DataGroupHashValues()),
        OptionalNamedType('ldsVersionInfo', LDSVersionInfo()),
    )


class SubjectPublicKeyInfo(Sequence):
    componentType = NamedTypes(
        NamedType('algorithm', AlgorithmIdentifier()),
        NamedType('subjectPublicKey', BitString()),
    )


id_icao = ObjectIdentifier((2, 23, 136))
id_icao_mrtd = ObjectIdentifier(id_icao + (1,))
id_icao_mrtdsecurity = ObjectIdentifier(id_icao_mrtd + (1,))
id_icao_ldsSecurityObject = ObjectIdentifier(id_icao_mrtdsecurity + (1,))


def asn1Length(data: bytes) -> tuple:
    """Decode an ASN.1 length field and return (length, bytes_consumed).

    >>> asn1Length(b"\\x22")
    (34, 1)
    >>> asn1Length(b"\\x81\\xaa")
    (170, 2)
    >>> asn1Length(b"\\x82\\xaa\\xbb")
    (43707, 3)

    @param data: A length value encoded in ASN.1 format.
    @type data: bytes
    @return: A tuple (decoded_length, encoding_size).
    @raise asn1Exception: If the field does not follow ASN.1 notation.
    """
    if data[0] <= 0x7F:
        return (binToHex(data[0]), 1)
    if data[0] == 0x81:
        return (binToHex(data[1]), 2)
    if data[0] == 0x82:
        return (binToHex(data[1:3]), 3)

    raise asn1Exception("Cannot decode the asn1 length from this field: " + binToHexRep(data))


def toAsn1Length(data: int) -> bytes:
    """Encode an integer as an ASN.1 length field.

    >>> binToHexRep(toAsn1Length(34))
    '22'
    >>> binToHexRep(toAsn1Length(170))
    '81aa'
    >>> binToHexRep(toAsn1Length(43707))
    '82aabb'

    @param data: The integer value to encode.
    @type data: int
    @return: The ASN.1 encoded length as bytes.
    @rtype: bytes
    @raise asn1Exception: If the value is out of range (must be 0 <= data <= 0xFFFF).
    """
    if data <= 0x7F:
        return hexToBin(data)
    if 0x80 <= data <= 0xFF:
        return b"\x81" + hexRepToBin("%02x" % data)
    if 0x0100 <= data <= 0xFFFF:
        return b"\x82" + hexRepToBin("%04x" % data)

    raise asn1Exception("The value is too big, must be <= FFFF")
