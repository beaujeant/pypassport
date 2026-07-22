"""Tests for DG14 (SecurityInfos) and DG15 (SubjectPublicKeyInfo) parsing."""

import json

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.doc9303.data_group import DataGroup14, DataGroup15
from pypassport.doc9303.security_info import (
    describe_spki_from_der,
    parse_security_infos,
    security_info_name,
)


# ---------------------------------------------------------------------------
# DER builders
# ---------------------------------------------------------------------------


def _wrap_dg(tag: int, body: bytes) -> bytes:
    """Wrap *body* in the DG outer TLV (single tag byte + ASN.1 length)."""
    n = len(body)
    if n <= 0x7F:
        length = bytes([n])
    elif n <= 0xFF:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + length + body


def _rsa_spki(modulus: int, exponent: int = 65537) -> bytes:
    rsa_key = univ.Sequence()
    rsa_key.setComponentByPosition(0, univ.Integer(modulus))
    rsa_key.setComponentByPosition(1, univ.Integer(exponent))
    rsa_der = der_encode(rsa_key)

    alg = univ.Sequence()
    alg.setComponentByPosition(0, univ.ObjectIdentifier("1.2.840.113549.1.1.1"))
    alg.setComponentByPosition(1, univ.Null(""))

    spki = univ.Sequence()
    spki.setComponentByPosition(0, alg)
    spki.setComponentByPosition(1, univ.BitString.fromOctetString(rsa_der))
    return der_encode(spki)


def _ec_spki(curve_oid: str, point: bytes) -> bytes:
    alg = univ.Sequence()
    alg.setComponentByPosition(0, univ.ObjectIdentifier("1.2.840.10045.2.1"))
    alg.setComponentByPosition(1, univ.ObjectIdentifier(curve_oid))

    spki = univ.Sequence()
    spki.setComponentByPosition(0, alg)
    spki.setComponentByPosition(1, univ.BitString.fromOctetString(point))
    return der_encode(spki)


def _security_info(oid_str, *integers, public_key_der=None):
    seq = univ.Sequence()
    pos = 0
    seq.setComponentByPosition(pos, univ.ObjectIdentifier(oid_str))
    pos += 1
    if public_key_der is not None:
        spki, _ = der_decode(public_key_der)
        seq.setComponentByPosition(pos, spki)
        pos += 1
    for value in integers:
        seq.setComponentByPosition(pos, univ.Integer(value))
        pos += 1
    return seq


def _security_infos_set(*infos) -> bytes:
    s = univ.SetOf(componentType=univ.Sequence())
    for i, info in enumerate(infos):
        s.setComponentByPosition(i, info)
    return der_encode(s)


# ---------------------------------------------------------------------------
# security_info_name
# ---------------------------------------------------------------------------


def test_security_info_name_chip_authentication():
    assert security_info_name("0.4.0.127.0.7.2.2.3.2.2") == "id-CA-ECDH-AES-CBC-CMAC-128"


def test_security_info_name_public_key():
    assert security_info_name("0.4.0.127.0.7.2.2.1.2") == "id-PK-ECDH"


def test_security_info_name_pace_derived():
    # Not in the explicit table — derived from the PACE OID table.
    assert security_info_name("0.4.0.127.0.7.2.2.4.2.2") == "id-PACE-ECDH-GM-AES-128"


def test_security_info_name_unknown_returns_oid():
    assert security_info_name("1.2.3.4") == "1.2.3.4"


# ---------------------------------------------------------------------------
# describe_spki_from_der
# ---------------------------------------------------------------------------


def test_describe_rsa_spki():
    modulus = (1 << 1023) | 0x1234567
    der = _rsa_spki(modulus, 65537)
    out = describe_spki_from_der(der)
    assert out["algorithm"] == "rsaEncryption"
    assert out["algorithm_oid"] == "1.2.840.113549.1.1.1"
    assert out["modulus_bits"] == 1024
    assert out["public_exponent"] == 65537
    assert out["modulus"] == format(modulus, "X")
    assert out["spki_der_hex"] == der.hex().upper()


def test_describe_ec_spki():
    point = b"\x04" + b"\x11" * 64
    der = _ec_spki("1.2.840.10045.3.1.7", point)
    out = describe_spki_from_der(der)
    assert out["algorithm"] == "ecPublicKey"
    assert out["curve"] == "prime256v1 (NIST P-256)"
    assert out["curve_oid"] == "1.2.840.10045.3.1.7"
    assert out["public_point"] == point.hex()


# ---------------------------------------------------------------------------
# parse_security_infos (DG14 content)
# ---------------------------------------------------------------------------


def test_parse_chip_authentication_info():
    ca = _security_info("0.4.0.127.0.7.2.2.3.2.2", 1, 0)  # version 1, keyId 0
    infos = parse_security_infos(_security_infos_set(ca))
    assert len(infos) == 1
    assert infos[0]["protocol"] == "id-CA-ECDH-AES-CBC-CMAC-128"
    assert infos[0]["version"] == 1
    assert infos[0]["key_id"] == 0
    assert infos[0]["required_data_der_hex"]
    assert infos[0]["security_info_der_hex"]


def test_parse_chip_authentication_public_key_info():
    ec_der = _ec_spki("1.2.840.10045.3.1.7", b"\x04" + b"\x22" * 64)
    pk = _security_info("0.4.0.127.0.7.2.2.1.2", 0, public_key_der=ec_der)  # keyId 0
    infos = parse_security_infos(_security_infos_set(pk))
    assert len(infos) == 1
    info = infos[0]
    assert info["protocol"] == "id-PK-ECDH"
    assert info["public_key"]["algorithm"] == "ecPublicKey"
    assert info["public_key"]["curve"] == "prime256v1 (NIST P-256)"
    assert info["key_id"] == 0


def test_parse_terminal_authentication_info():
    ta = _security_info("0.4.0.127.0.7.2.2.2", 1)
    infos = parse_security_infos(_security_infos_set(ta))
    assert infos[0]["protocol"] == "id-TA"
    assert infos[0]["version"] == 1


def test_parse_multiple_security_infos():
    ca = _security_info("0.4.0.127.0.7.2.2.3.2.2", 1, 0)
    ec_der = _ec_spki("1.2.840.10045.3.1.7", b"\x04" + b"\x33" * 64)
    pk = _security_info("0.4.0.127.0.7.2.2.1.2", 0, public_key_der=ec_der)
    infos = parse_security_infos(_security_infos_set(ca, pk))
    protocols = {i["protocol"] for i in infos}
    assert protocols == {"id-CA-ECDH-AES-CBC-CMAC-128", "id-PK-ECDH"}


def test_parse_security_infos_keeps_unexpected_entries_visible():
    body = der_encode(univ.SetOf(componentType=univ.Integer()).setComponentByPosition(0, univ.Integer(7)))
    infos = parse_security_infos(body)

    assert infos == [
        {
            "unexpected_tag": "02",
            "security_info_der_hex": "020107",
            "value_hex": "07",
        }
    ]


# ---------------------------------------------------------------------------
# DataGroup14 / DataGroup15 end-to-end
# ---------------------------------------------------------------------------


def test_datagroup14_parses_security_infos():
    ca = _security_info("0.4.0.127.0.7.2.2.3.2.2", 1, 0)
    body = _security_infos_set(ca)
    dg = DataGroup14(file=_wrap_dg(0x6E, body))
    assert "security_infos" in dg
    assert "raw" not in dg
    assert dg["security_infos"][0]["protocol"] == "id-CA-ECDH-AES-CBC-CMAC-128"
    rendered = json.loads(dg.to_json())
    assert rendered["name"] == "DG14"
    assert rendered["data"]["security_infos"][0]["security_info_der_hex"]


def test_datagroup15_parses_rsa_key():
    modulus = (1 << 1023) | 0xABCDEF
    body = _rsa_spki(modulus, 65537)
    dg = DataGroup15(file=_wrap_dg(0x6F, body))
    assert "raw" not in dg
    assert dg["algorithm"] == "rsaEncryption"
    assert dg["modulus_bits"] == 1024
    assert dg["public_exponent"] == 65537
    # The raw body remains untouched for active_authentication.
    assert dg.body == body
    rendered = json.loads(dg.to_json())
    assert rendered["name"] == "DG15"
    assert rendered["data"]["spki_der_hex"] == body.hex().upper()


def test_datagroup15_parses_ec_key():
    point = b"\x04" + b"\x44" * 64
    body = _ec_spki("1.2.840.10045.3.1.7", point)
    dg = DataGroup15(file=_wrap_dg(0x6F, body))
    assert dg["algorithm"] == "ecPublicKey"
    assert dg["curve"] == "prime256v1 (NIST P-256)"
    assert dg["public_point"] == point.hex()
