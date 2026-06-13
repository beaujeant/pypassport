"""Unit tests for the APDU interceptor and its ISO 7816 transport hook.

These tests use a fake reader (no PC/SC, no card). The fake records every raw
APDU it is asked to transmit so we can assert precisely what the chip would
have received after interception.
"""

import pytest

from pypassport.interceptor import Interceptor, Rule
from pypassport.iso7816 import (
    APDUCommand,
    APDUDroppedException,
    ISO7816,
    ISO7816Exception,
)


class FakeReader:
    """Minimal reader stub: echoes a fixed success response and logs sends."""

    def __init__(self, response=(b"", 0x90, 0x00)):
        self.response = response
        self.sent = []  # list of raw command lists actually transmitted

    def transmit(self, raw):
        self.sent.append(raw)
        data, sw1, sw2 = self.response
        return list(data), sw1, sw2


@pytest.fixture(autouse=True)
def fresh_interceptor():
    """Each test starts from the transparent no-op default and restores it."""
    Interceptor().reset()
    yield
    Interceptor().reset()


def _cmd(cla="00", ins="A4", p1="02", p2="0C", data="3F00", le=""):
    return APDUCommand(cla, ins, p1, p2, data=data, le=le)


# ---------------------------------------------------------------------------
# Interceptor unit behaviour
# ---------------------------------------------------------------------------


def test_singleton_identity():
    assert Interceptor() is Interceptor()


def test_default_is_noop():
    interceptor = Interceptor()
    cmd = _cmd()
    # Disabled, no rules: returns the same object untouched.
    assert interceptor.intercept(cmd) is cmd


def test_callback_edit_returns_edited_command():
    interceptor = Interceptor()
    interceptor.enabled = True

    def edit(apdu):
        return APDUCommand(apdu.cla, apdu.ins, "0C", "00", data=apdu.data)

    interceptor.callback = edit
    out = interceptor.intercept(_cmd())
    assert out.p1 == "0C"
    assert out.p2 == "00"


def test_callback_drop_returns_none():
    interceptor = Interceptor()
    interceptor.enabled = True
    interceptor.callback = lambda apdu: None
    assert interceptor.intercept(_cmd()) is None
    assert interceptor.history[-1]["action"] == "drop"


def test_callback_ignored_when_disabled():
    interceptor = Interceptor()
    interceptor.enabled = False
    interceptor.callback = lambda apdu: None  # would drop if consulted
    cmd = _cmd()
    assert interceptor.intercept(cmd) is cmd


# ---------------------------------------------------------------------------
# Match-&-replace rules (applied automatically when interception is off)
# ---------------------------------------------------------------------------


def test_rule_rewrites_matching_command():
    interceptor = Interceptor()
    interceptor.add_rule(Rule(match={"ins": "A4"}, replace={"p1": "08"}))
    out = interceptor.intercept(_cmd(ins="A4", p1="02"))
    assert out.p1 == "08"
    assert interceptor.history[-1]["action"] == "rule"


def test_rule_does_not_touch_non_matching_command():
    interceptor = Interceptor()
    interceptor.add_rule(Rule(match={"ins": "B0"}, replace={"p1": "FF"}))
    cmd = _cmd(ins="A4")
    assert interceptor.intercept(cmd) is cmd


def test_rule_match_is_case_insensitive():
    interceptor = Interceptor()
    interceptor.add_rule(Rule(match={"ins": "a4"}, replace={"p2": "00"}))
    out = interceptor.intercept(_cmd(ins="A4", p2="0C"))
    assert out.p2 == "00"


def test_rule_replacing_data_recomputes_lc():
    interceptor = Interceptor()
    interceptor.add_rule(Rule(match={"ins": "A4"}, replace={"data": "3F0001"}))
    out = interceptor.intercept(_cmd(ins="A4", data="3F00"))
    assert out.data == "3F0001"
    assert out.lc == "03"  # 3 bytes, recomputed from new data


def test_rules_disabled_when_interception_on():
    interceptor = Interceptor()
    interceptor.enabled = True
    interceptor.callback = lambda apdu: apdu  # forward unchanged
    interceptor.add_rule(Rule(match={"ins": "A4"}, replace={"p1": "FF"}))
    out = interceptor.intercept(_cmd(ins="A4", p1="02"))
    assert out.p1 == "02"  # rule NOT applied while interactive mode is active


def test_disabled_rule_is_skipped():
    interceptor = Interceptor()
    interceptor.add_rule(Rule(match={"ins": "A4"}, replace={"p1": "FF"}, enabled=False))
    cmd = _cmd(ins="A4")
    assert interceptor.intercept(cmd) is cmd


# ---------------------------------------------------------------------------
# ISO7816.transmit integration (the transport hook)
# ---------------------------------------------------------------------------


def test_transmit_noop_sends_unmodified_command():
    reader = FakeReader()
    iso = ISO7816(reader)
    iso.transmit(_cmd(ins="A4", p1="02", p2="0C", data="3F00"))
    assert len(reader.sent) == 1
    # 00 A4 02 0C 02 3F00
    assert reader.sent[0] == [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x3F, 0x00]


def test_transmit_applies_edit_before_send():
    Interceptor().enabled = True
    Interceptor().callback = lambda apdu: APDUCommand(
        apdu.cla, apdu.ins, "08", "04", data=apdu.data
    )
    reader = FakeReader()
    iso = ISO7816(reader)
    iso.transmit(_cmd(ins="A4", p1="02", p2="0C", data="3F00"))
    # The chip receives the EDITED P1/P2, not the originals.
    assert reader.sent[0][2] == 0x08
    assert reader.sent[0][3] == 0x04


def test_transmit_drop_does_not_touch_card():
    Interceptor().enabled = True
    Interceptor().callback = lambda apdu: None
    reader = FakeReader()
    iso = ISO7816(reader)
    with pytest.raises(APDUDroppedException):
        iso.transmit(_cmd())
    assert reader.sent == []  # nothing ever reached the reader


def test_drop_does_not_advance_ssc_so_later_traffic_stays_in_sync():
    """A dropped APDU must not advance the SSC; the next real send must."""

    class FakeCiphering:
        def __init__(self):
            self.ssc = 0
            self.protect_calls = 0

        def protect(self, apdu):
            self.protect_calls += 1
            self.ssc += 1  # SM advances the SSC only on a real send
            return apdu

        def unprotect(self, response):
            return response

    sm = FakeCiphering()
    reader = FakeReader()
    iso = ISO7816(reader)
    iso.ciphering = sm

    # Drop the first command: protect() must NOT run, SSC unchanged.
    Interceptor().enabled = True
    Interceptor().callback = lambda apdu: None
    with pytest.raises(APDUDroppedException):
        iso.transmit(_cmd())
    assert sm.protect_calls == 0
    assert sm.ssc == 0

    # Now forward a command: SM runs exactly once, SSC advances by one.
    Interceptor().callback = lambda apdu: apdu
    iso.transmit(_cmd())
    assert sm.protect_calls == 1
    assert sm.ssc == 1
    assert len(reader.sent) == 1


def test_transmit_auto_rewrites_via_rule_when_off():
    Interceptor().enabled = False
    Interceptor().add_rule(Rule(match={"ins": "B0"}, replace={"p1": "7F"}))
    reader = FakeReader()
    iso = ISO7816(reader)
    iso.transmit(APDUCommand("00", "B0", "00", "00", le="08"))
    assert reader.sent[0][2] == 0x7F  # P1 rewritten by the rule


def test_transmit_success_returns_response_data():
    reader = FakeReader(response=(b"\x01\x02\x03", 0x90, 0x00))
    iso = ISO7816(reader)
    out = iso.transmit(_cmd())
    assert out == b"\x01\x02\x03"


def test_transmit_error_status_raises():
    reader = FakeReader(response=(b"", 0x6A, 0x82))
    iso = ISO7816(reader)
    with pytest.raises(ISO7816Exception):
        iso.transmit(_cmd())
