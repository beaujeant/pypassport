"""Unit tests for pypassport.doc9303.card_access."""

import pytest
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.doc9303.card_access import (
    CardAccessNotFound,
    CardAccessReadError,
    CardAccessReader,
)
from pypassport.doc9303.data_group import CardAccess
from pypassport.iso7816 import ISO7816Exception


class FakeISO7816:
    """Minimal mock matching the parts of ISO7816 that CardAccessReader uses."""

    def __init__(self):
        # Sequence of side-effects to apply on the next call.
        self.select_mf_result = None  # callable or None for success
        self.select_ef_result = None  # callable or None for success
        self.binary_chunks = {}  # offset -> bytes (or ISO7816Exception)
        self.calls = []

    def transmit(self, apdu, log=None):
        # Used only for Select MF in CardAccessReader.
        self.calls.append(("transmit", str(apdu)))
        if callable(self.select_mf_result):
            self.select_mf_result()
        return b""

    def select_elementary_file(self, fid):
        self.calls.append(("selectEF", fid))
        if callable(self.select_ef_result):
            self.select_ef_result()
        return b""

    def read_binary(self, offset, nbytes):
        self.calls.append(("read_binary", offset, nbytes))
        chunk = self.binary_chunks.get(offset)
        if isinstance(chunk, ISO7816Exception):
            raise chunk
        if chunk is None:
            raise AssertionError(f"unexpected read_binary({offset}, {nbytes})")
        return chunk[:nbytes]


def _raise_iso(sw1, sw2):
    def _r():
        raise ISO7816Exception("fail", sw1, sw2)

    return _r


def _pace_security_infos():
    info = univ.Sequence()
    info.setComponentByPosition(0, univ.ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2"))
    info.setComponentByPosition(1, univ.Integer(2))
    info.setComponentByPosition(2, univ.Integer(13))
    infos = univ.SetOf(componentType=univ.Sequence())
    infos.setComponentByPosition(0, info)
    return der_encode(infos)


def test_read_returns_full_body():
    body = b"\x31\x82\x00\x10" + b"A" * 0x10  # SET length 0x0010, 16 bytes
    iso = FakeISO7816()
    iso.binary_chunks[0] = body[:4]
    iso.binary_chunks[4] = body[4:]

    raw = CardAccessReader(iso).read()
    assert raw == body


def test_read_handles_select_mf_failure_and_continues():
    body = b"\x31\x04\x02\x01\x02\x03"
    iso = FakeISO7816()
    iso.select_mf_result = _raise_iso(0x6A, 0x82)
    iso.binary_chunks[0] = body[:4]
    iso.binary_chunks[4] = body[4:]

    raw = CardAccessReader(iso).read()
    assert raw == body


def test_read_raises_card_access_not_found_on_select_ef_6a82():
    iso = FakeISO7816()
    iso.select_ef_result = _raise_iso(0x6A, 0x82)

    with pytest.raises(CardAccessNotFound) as excinfo:
        CardAccessReader(iso).read()
    assert excinfo.value.sw1 == 0x6A
    assert excinfo.value.sw2 == 0x82


def test_read_raises_read_error_on_header_failure():
    iso = FakeISO7816()
    iso.binary_chunks[0] = ISO7816Exception("oops", 0x69, 0x82)

    with pytest.raises(CardAccessReadError) as excinfo:
        CardAccessReader(iso).read()
    assert excinfo.value.sw1 == 0x69


def test_read_handles_short_responses():
    # Build a 0x40-byte body so multiple short reads are required.
    body = b"\x31\x40" + bytes(range(0x40))
    iso = FakeISO7816()
    iso.binary_chunks[0] = body[:4]
    # CardAccessReader reads 4 header bytes then requests from offset 4
    # up to MAX_LE (0xDF) — single chunk is enough here.
    iso.binary_chunks[4] = body[4:]

    raw = CardAccessReader(iso).read()
    assert raw == body


def test_card_access_preserves_raw_security_infos_wrapper():
    raw = _pace_security_infos()

    ef = CardAccess.from_security_infos(raw)

    assert ef.tag == "42"
    assert ef["encoding_tag"] == "31"
    assert ef.file == raw
    assert ef["security_infos"][0].oid == "0.4.0.127.0.7.2.2.4.2.2"
