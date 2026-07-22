"""Unit tests for pypassport.doc9303.security_info."""

import pytest
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.doc9303.security_info import (
    PACEInfo,
    SecurityInfoParseError,
    SecurityInfoParser,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _security_info(oid_str, version, parameter_id=None):
    seq = univ.Sequence()
    seq.setComponentByPosition(0, univ.ObjectIdentifier(oid_str))
    seq.setComponentByPosition(1, univ.Integer(version))
    if parameter_id is not None:
        seq.setComponentByPosition(2, univ.Integer(parameter_id))
    return seq


def _security_infos_set(*infos):
    s = univ.SetOf(componentType=univ.Sequence())
    for i, info in enumerate(infos):
        s.setComponentByPosition(i, info)
    return der_encode(s)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_single_pace_info():
    data = _security_infos_set(
        _security_info("0.4.0.127.0.7.2.2.4.2.2", 2, 13),
    )
    infos = SecurityInfoParser().parse(data)
    assert len(infos) == 1
    info = infos[0]
    assert info.oid == "0.4.0.127.0.7.2.2.4.2.2"
    assert info.version == 2
    assert info.parameter_id == 13
    assert info.key_agreement == "ECDH"
    assert info.mapping == "GM"
    assert info.cipher == "AES"
    assert info.key_size == 128
    assert info.is_known()


def test_parse_pace_info_without_parameter_id():
    data = _security_infos_set(
        _security_info("0.4.0.127.0.7.2.2.4.1.2", 2),
    )
    infos = SecurityInfoParser().parse(data)
    assert len(infos) == 1
    assert infos[0].parameter_id is None
    assert infos[0].key_agreement == "DH"


def test_parse_skips_non_pace_security_infos():
    # ChipAuthenticationPublicKeyInfo OID prefix is 0.4.0.127.0.7.2.2.1
    other = _security_info("0.4.0.127.0.7.2.2.1.2", 1)
    pace = _security_info("0.4.0.127.0.7.2.2.4.2.4", 2, 13)
    data = _security_infos_set(other, pace)
    infos = SecurityInfoParser().parse(data)
    assert len(infos) == 1
    assert infos[0].oid == "0.4.0.127.0.7.2.2.4.2.4"


def test_parse_multiple_pace_infos():
    data = _security_infos_set(
        _security_info("0.4.0.127.0.7.2.2.4.2.2", 2, 13),
        _security_info("0.4.0.127.0.7.2.2.4.2.4", 2, 13),
    )
    infos = SecurityInfoParser().parse(data)
    oids = {info.oid for info in infos}
    assert oids == {
        "0.4.0.127.0.7.2.2.4.2.2",
        "0.4.0.127.0.7.2.2.4.2.4",
    }


def test_parse_empty_bytes_raises():
    with pytest.raises(SecurityInfoParseError):
        SecurityInfoParser().parse(b"")


def test_parse_garbage_raises():
    with pytest.raises(SecurityInfoParseError):
        SecurityInfoParser().parse(b"\xff\xff\xff\xff")


def test_select_supported_picks_strongest_first():
    parser = SecurityInfoParser()
    infos = [
        PACEInfo(oid="0.4.0.127.0.7.2.2.4.2.2", version=2, parameter_id=13),
        PACEInfo(oid="0.4.0.127.0.7.2.2.4.2.4", version=2, parameter_id=13),
    ]
    chosen = parser.select_supported(infos)
    # The default preference list ranks AES-256 above AES-128.
    assert chosen.oid == "0.4.0.127.0.7.2.2.4.2.4"


def test_select_supported_returns_none_for_unknown():
    parser = SecurityInfoParser()
    infos = [PACEInfo(oid="1.2.3.4.5", version=2)]
    assert parser.select_supported(infos) is None


def test_select_supported_respects_custom_supported_list():
    parser = SecurityInfoParser(supported_oids=["0.4.0.127.0.7.2.2.4.2.2"])
    infos = [
        PACEInfo(oid="0.4.0.127.0.7.2.2.4.2.4", version=2, parameter_id=13),
        PACEInfo(oid="0.4.0.127.0.7.2.2.4.2.2", version=2, parameter_id=13),
    ]
    chosen = parser.select_supported(infos)
    assert chosen.oid == "0.4.0.127.0.7.2.2.4.2.2"
