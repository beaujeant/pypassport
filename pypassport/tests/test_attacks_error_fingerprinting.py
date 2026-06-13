"""Unit tests for the error-fingerprinting attack.

A fake reader (no PC/SC, no card) returns a fixed status word so the
add/identify round-trip and the JSON persistence can be exercised offline.
"""

import json

import pytest

from pypassport.attacks.error_fingerprinting import (
    ErrorFingerprinting,
    ErrorFingerprintingException,
)
from pypassport.iso7816 import ISO7816


class FakeReader:
    """Returns a single, fixed (data, sw1, sw2) response for every command."""

    def __init__(self, response=(b"", 0x90, 0x00)):
        self.response = response

    def transmit(self, raw):
        data, sw1, sw2 = self.response
        return list(data), sw1, sw2


def _make_iso(response):
    iso = ISO7816(FakeReader(response))
    # Neutralise rstConnection: it would otherwise drive a real PC/SC reader.
    iso.rstConnection = lambda *a, **k: None
    return iso


# cla=00 ins=FF p1=00 p2=00 lc="" data="" le=00  ->  concatenated query key
UNKNOWN_INS_QUERY = "00FF000000"


def test_send_custom_reports_error_status():
    ef = ErrorFingerprinting(_make_iso((b"", 0x6D, 0x00)), path="unused-only-on-add.json")
    success, response = ef.sendCustom(ins="FF")
    assert success is False
    assert (response.sw1, response.sw2) == (0x6D, 0x00)


def test_add_identify_roundtrip(tmp_path):
    path = str(tmp_path / "errors.json")
    ef = ErrorFingerprinting(_make_iso((b"", 0x6D, 0x00)), path=path)

    ef.addError(UNKNOWN_INS_QUERY, ef.sendCustom(ins="FF"), "BEL", "2020")

    assert ef.identify(ins="FF") == ["BEL 2020"]


def test_database_persisted_as_json_and_reloaded(tmp_path):
    path = tmp_path / "errors.json"
    ef = ErrorFingerprinting(_make_iso((b"", 0x6D, 0x00)), path=str(path))
    ef.addError(UNKNOWN_INS_QUERY, ef.sendCustom(ins="FF"), "BEL", "2020")

    # The file is human-readable JSON (not pickle) and structured as expected.
    stored = json.loads(path.read_text())
    assert stored[UNKNOWN_INS_QUERY]["0x6d 0x0"]["BEL"] == ["2020"]

    # A fresh instance loads the same DB and identifies the chip.
    reloaded = ErrorFingerprinting(_make_iso((b"", 0x6D, 0x00)), path=str(path))
    assert reloaded.identify(ins="FF") == ["BEL 2020"]


def test_add_error_rejects_successful_query(tmp_path):
    ef = ErrorFingerprinting(_make_iso((b"", 0x90, 0x00)), path=str(tmp_path / "e.json"))
    with pytest.raises(ErrorFingerprintingException):
        ef.addError("00A4000000", ef.sendCustom(ins="A4"), "BEL", "2020")


def test_identify_rejects_successful_query(tmp_path):
    ef = ErrorFingerprinting(_make_iso((b"", 0x90, 0x00)), path=str(tmp_path / "e.json"))
    with pytest.raises(ErrorFingerprintingException):
        ef.identify(ins="A4")
