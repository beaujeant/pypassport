"""Tests for wire-level APDU recording in ISO7816.transmit.

Each transmit records both the cleartext APDU and the bytes actually exchanged
over PC/SC. With SM off the two views are identical; with SM on the wire view
holds the protected frame (request) and the raw response before unprotect.
"""

import pytest

from pypassport.iso7816 import ISO7816, APDUCommand, APDUResponse
from pypassport.apdu_history import APDUHistory


class _FakeReader:
    """Returns a canned (data, sw1, sw2) for whatever bytes it is handed."""

    def __init__(self, response):
        self.response = response
        self.sent = None

    def transmit(self, data):
        self.sent = data
        return self.response


@pytest.fixture(autouse=True)
def _clear_history():
    APDUHistory.get().clear()
    yield
    APDUHistory.get().clear()


def test_plaintext_wire_matches_cleartext():
    reader = _FakeReader(([], 0x90, 0x00))
    iso = ISO7816(reader)
    iso.ciphering = False

    cmd = APDUCommand("00", "A4", "02", "0C", data="011E")
    iso.transmit(cmd, full=True)

    tx = APDUHistory.get()[-1]
    assert tx.sm_active is False
    # Wire request equals the cleartext command bytes.
    assert tx.wire_request_hex == "00A4020C02011E"
    # Wire response equals the cleartext response (no data, just SW).
    assert tx.wire_response_hex == "9000"


class _FakeAesSM:
    """Stand-in SM layer: protect rewrites the command, unprotect decodes."""

    def __init__(self, protected, decoded):
        self._protected = protected
        self._decoded = decoded

    def protect(self, apdu):
        return self._protected

    def unprotect(self, rapdu):
        return self._decoded


def test_sm_wire_holds_protected_frame_and_raw_response():
    # Raw response the chip returns: DO87 (enc data) + DO99 (SW) + DO8E (MAC).
    raw_data = [0x87, 0x02, 0x01, 0xAB, 0x99, 0x02, 0x90, 0x00,
                0x8E, 0x02, 0xCC, 0xDD]
    reader = _FakeReader((raw_data, 0x90, 0x00))

    protected = APDUCommand("0C", "A4", "02", "0C", data="8702CAFE", le="00")
    decoded = APDUResponse([0x01, 0x02], 0x90, 0x00)

    iso = ISO7816(reader)
    iso.ciphering = _FakeAesSM(protected, decoded)

    cleartext = APDUCommand("00", "A4", "02", "0C", data="011E")
    iso.transmit(cleartext, full=True)

    tx = APDUHistory.get()[-1]
    assert tx.sm_active is True
    assert tx.sm_type == "AES"

    # Cleartext view: the original, decoded request and response.
    assert tx.request_data == "011E"
    assert tx.response_data == "0102"

    # Wire view: protected request frame and the raw response + SW before
    # unprotect, including the 87/99/8E DOs.
    assert tx.wire_request_hex == "0CA4020C048702CAFE00"
    assert tx.wire_response_hex == "870201AB99029000" + "8E02CCDD" + "9000"

    # The bytes recorded as the wire request are exactly what hit the reader.
    assert reader.sent == protected.raw()
