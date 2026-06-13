"""Unit tests for the MAC-traceability decision logic.

The card-facing helpers (_getPair / rstBAC / _sendPair) are stubbed so the
pure decision logic in isVulnerable() can be exercised without a card. The
key property under test: a positive *response-difference* result must never
be overwritten by the timing comparison.
"""

from pypassport.attacks.mac_traceability import MacTraceability
from pypassport.doc9303.mrz import MRZ
from pypassport.iso7816 import ISO7816, APDUResponse


VALID_MRZ = MRZ(("L898902C", "690806", "940623")).mrz


class FakeReader:
    def __init__(self, response=(b"", 0x90, 0x00)):
        self.response = response

    def transmit(self, raw):
        data, sw1, sw2 = self.response
        return list(data), sw1, sw2


def _make_mt():
    iso = ISO7816(FakeReader())
    iso.rstConnection = lambda *a, **k: None
    mt = MacTraceability(iso, mrz=VALID_MRZ)
    mt._getPair = lambda: b"\x00" * 40
    mt.rstBAC = lambda: None
    return mt


def _drive(mt, ans1, ans2):
    """Feed the two _sendPair() calls of isVulnerable in order."""
    responses = iter([ans1, ans2])
    mt._sendPair = lambda cmd_data=None: next(responses)
    return mt.isVulnerable(CO=1.7)


def test_different_status_word_is_vulnerable_even_with_short_timing():
    # The historic bug: a positive response-difference verdict was clobbered
    # by the timing branch. Status words differ but timing is identical.
    mt = _make_mt()
    ans1 = (APDUResponse(b"", 0x69, 0x82), 0.0)
    ans2 = (APDUResponse(b"", 0x90, 0x00), 0.0)
    vulnerable, comment = _drive(mt, ans1, ans2)
    assert vulnerable is True
    assert comment


def test_different_response_data_is_vulnerable():
    mt = _make_mt()
    ans1 = (APDUResponse(b"\x01", 0x90, 0x00), 0.0)
    ans2 = (APDUResponse(b"\x02", 0x90, 0x00), 0.0)
    vulnerable, _ = _drive(mt, ans1, ans2)
    assert vulnerable is True


def test_identical_response_with_long_timing_is_vulnerable():
    mt = _make_mt()
    # Same answer both times, but the valid-MAC reply is markedly slower.
    ans1 = (APDUResponse(b"", 0x69, 0x82), 0.0)
    ans2 = (APDUResponse(b"", 0x69, 0x82), 0.010)  # 10 ms > 1.7 ms cut-off
    vulnerable, _ = _drive(mt, ans1, ans2)
    assert vulnerable is True


def test_identical_response_with_short_timing_is_not_vulnerable():
    mt = _make_mt()
    ans1 = (APDUResponse(b"", 0x69, 0x82), 0.0)
    ans2 = (APDUResponse(b"", 0x69, 0x82), 0.0)
    vulnerable, _ = _drive(mt, ans1, ans2)
    assert vulnerable is False
