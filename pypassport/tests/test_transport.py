"""Tests for ISO7816.transmit transport behaviour.

Covers the paths the wire-recording suite does not: the full-vs-raise return
contract, Secure-Messaging type detection (3DES vs AES), the history record
written for an ordinary transaction, and the interceptor drop short-circuit
that must record the dropped command and raise without touching the chip.

All of it runs against a fake reader so no PC/SC service is needed.
"""

import pytest

from pypassport.iso7816 import (
    ISO7816,
    APDUCommand,
    APDUResponse,
    ISO7816Exception,
    APDUDroppedException,
)
from pypassport.apdu_history import APDUHistory
from pypassport.interceptor import Interceptor


class _FakeReader:
    """Returns a canned (data, sw1, sw2) for whatever bytes it is handed."""

    def __init__(self, response):
        self.response = response
        self.sent = None

    def transmit(self, data):
        self.sent = data
        return self.response


class _FakeSM:
    """Minimal SM layer: protect/unprotect pass the APDU through unchanged.

    The class *name* is what transmit() inspects to label the SM type, so
    subclasses below stand in for the 3DES and AES layers.
    """

    def protect(self, apdu):
        return apdu

    def unprotect(self, rapdu):
        return rapdu


class FakeAesSecureMessaging(_FakeSM):
    pass


class FakeSecureMessaging(_FakeSM):  # 3DES: name has no "Aes"
    pass


@pytest.fixture(autouse=True)
def _clean_state():
    APDUHistory.get().clear()
    Interceptor().reset()
    yield
    APDUHistory.get().clear()
    Interceptor().reset()


# -- return contract --------------------------------------------------------


def test_success_without_full_returns_data_bytes():
    reader = _FakeReader(([0x01, 0x02, 0x03], 0x90, 0x00))
    iso = ISO7816(reader)

    result = iso.transmit(APDUCommand("00", "B0", "00", "00", le="03"))
    assert result == bytes([0x01, 0x02, 0x03])


def test_full_returns_response_object_even_on_error_status():
    # 6A82 (file not found) is not success, but full=True must still return the
    # response object rather than raising.
    reader = _FakeReader(([], 0x6A, 0x82))
    iso = ISO7816(reader)

    resp = iso.transmit(APDUCommand("00", "A4", "02", "0C", data="0102"), full=True)
    assert isinstance(resp, APDUResponse)
    assert (resp.sw1, resp.sw2) == (0x6A, 0x82)
    assert resp.status == "File not found"


def test_non_success_status_raises_iso7816_exception():
    reader = _FakeReader(([], 0x69, 0x82))  # security status not satisfied
    iso = ISO7816(reader)

    with pytest.raises(ISO7816Exception) as excinfo:
        iso.transmit(APDUCommand("00", "B0", "00", "00", le="01"))
    assert excinfo.value.sw1 == 0x69
    assert excinfo.value.sw2 == 0x82


# -- SM type detection ------------------------------------------------------


def test_sm_type_detected_as_3des():
    reader = _FakeReader(([], 0x90, 0x00))
    iso = ISO7816(reader)
    iso.ciphering = FakeSecureMessaging()

    iso.transmit(APDUCommand("00", "A4", "02", "0C", data="011E"), full=True)

    tx = APDUHistory.get()[-1]
    assert tx.sm_active is True
    assert tx.sm_type == "3DES"


def test_sm_type_detected_as_aes():
    reader = _FakeReader(([], 0x90, 0x00))
    iso = ISO7816(reader)
    iso.ciphering = FakeAesSecureMessaging()

    iso.transmit(APDUCommand("00", "A4", "02", "0C", data="011E"), full=True)

    tx = APDUHistory.get()[-1]
    assert tx.sm_active is True
    assert tx.sm_type == "AES"


def test_no_sm_records_inactive():
    reader = _FakeReader(([], 0x90, 0x00))
    iso = ISO7816(reader)
    iso.ciphering = False

    iso.transmit(APDUCommand("00", "A4", "02", "0C", data="011E"), full=True)

    tx = APDUHistory.get()[-1]
    assert tx.sm_active is False
    assert tx.sm_type == ""


# -- history recording ------------------------------------------------------


def test_history_records_cleartext_request_and_response_and_source():
    reader = _FakeReader(([0xAB, 0xCD], 0x90, 0x00))
    iso = ISO7816(reader)

    iso.transmit(APDUCommand("00", "B0", "00", "00", le="02"), source="forge", full=True)

    assert len(APDUHistory.get()) == 1
    tx = APDUHistory.get()[-1]
    assert tx.request_cla == "00" and tx.request_ins == "B0"
    assert tx.response_data == "ABCD"
    assert (tx.response_sw1, tx.response_sw2) == (0x90, 0x00)
    assert tx.source == "forge"


def test_raise_path_still_records_the_transaction():
    reader = _FakeReader(([], 0x6A, 0x82))
    iso = ISO7816(reader)

    with pytest.raises(ISO7816Exception):
        iso.transmit(APDUCommand("00", "A4", "02", "0C", data="0102"))

    # The record is written before the raise, so failed reads stay visible.
    assert len(APDUHistory.get()) == 1
    assert (APDUHistory.get()[-1].response_sw1, APDUHistory.get()[-1].response_sw2) == (0x6A, 0x82)


# -- interceptor drop -------------------------------------------------------


def test_dropped_command_records_and_raises_without_touching_reader():
    reader = _FakeReader(([0x01], 0x90, 0x00))
    iso = ISO7816(reader)

    interceptor = Interceptor()
    interceptor.enabled = True
    interceptor.callback = lambda apdu: None  # drop everything

    cmd = APDUCommand("00", "A4", "02", "0C", data="011E")
    with pytest.raises(APDUDroppedException):
        iso.transmit(cmd)

    # The reader was never contacted ...
    assert reader.sent is None
    # ... but the drop is recorded with an explanatory comment.
    assert len(APDUHistory.get()) == 1
    tx = APDUHistory.get()[-1]
    assert tx.comment == "Dropped by interceptor"
    assert (tx.response_sw1, tx.response_sw2) == (0, 0)


def test_interceptor_edit_is_what_reaches_the_reader():
    reader = _FakeReader(([], 0x90, 0x00))
    iso = ISO7816(reader)

    edited = APDUCommand("00", "B0", "00", "00", le="04")
    interceptor = Interceptor()
    interceptor.enabled = True
    interceptor.callback = lambda apdu: edited

    iso.transmit(APDUCommand("00", "B0", "00", "00", le="01"), full=True)

    # The bytes that hit the reader are the edited command's bytes, and the
    # history records the post-edit cleartext.
    assert reader.sent == edited.raw()
    assert APDUHistory.get()[-1].request_le == "04"
