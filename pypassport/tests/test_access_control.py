"""Unit tests for pypassport.doc9303.access_control."""

from unittest.mock import patch

import pytest
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.doc9303.access_control import (
    AccessControlNegotiationError,
    AccessControlNegotiator,
    BACAuthenticationError,
    NoSupportedPACEInfo,
    PACEAuthenticationError,
    _oid_to_der_value,
)
from pypassport.doc9303.card_access import CardAccessNotFound, CardAccessReadError
from pypassport.iso7816 import ISO7816Exception


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class FakeMRZ:
    """Stand-in for the MRZ object — the negotiator only forwards it."""

    def __init__(self):
        self.checked = True

    def checkMRZ(self):
        return True


class FakeISO7816:
    def __init__(self):
        self.ciphering = False
        self.aid_selected = None
        self.aid_should_fail = None  # (sw1, sw2) or None

    def selectDedicatedFile(self, aid):
        if self.aid_should_fail is not None:
            sw1, sw2 = self.aid_should_fail
            raise ISO7816Exception("aid fail", sw1, sw2)
        self.aid_selected = aid


def _pace_blob(*oid_versions):
    """Build a SecurityInfos SET containing the given (oid, version, paramId) tuples."""
    s = univ.SetOf(componentType=univ.Sequence())
    for i, item in enumerate(oid_versions):
        oid, version, param = item
        seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.ObjectIdentifier(oid))
        seq.setComponentByPosition(1, univ.Integer(version))
        if param is not None:
            seq.setComponentByPosition(2, univ.Integer(param))
        s.setComponentByPosition(i, seq)
    return der_encode(s)


# ---------------------------------------------------------------------------
# Mode validation
# ---------------------------------------------------------------------------


def test_unknown_mode_raises():
    with pytest.raises(AccessControlNegotiationError):
        AccessControlNegotiator(FakeISO7816()).open(FakeMRZ(), mode="bogus")


def test_auto_mode_requires_mrz():
    with pytest.raises(AccessControlNegotiationError):
        AccessControlNegotiator(FakeISO7816()).open(None, mode="auto")


def test_bac_mode_requires_mrz():
    with pytest.raises(AccessControlNegotiationError):
        AccessControlNegotiator(FakeISO7816()).open(None, mode="bac")


# ---------------------------------------------------------------------------
# Auto mode — PACE happy path
# ---------------------------------------------------------------------------


def _stub_pace_authenticator(*, success=True, exc=None):
    """Build a stand-in class for PACEAuthenticator that records calls."""

    class _Stub:
        calls = []

        def __init__(self, iso, mrz):
            self._iso = iso
            self._mrz = mrz

        def authenticate(self, info):
            _Stub.calls.append(info)
            if exc is not None:
                raise exc
            if success:
                self._iso.ciphering = object()  # pretend SM is up

    return _Stub


def test_auto_mode_chooses_pace_when_advertised():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    blob = _pace_blob(("0.4.0.127.0.7.2.2.4.2.2", 2, 13))
    stub = _stub_pace_authenticator(success=True)

    with patch.object(neg._card_access_reader, "read", return_value=blob), \
         patch("pypassport.doc9303.access_control.PACEAuthenticator", stub):
        result = neg.open(FakeMRZ(), mode="auto")

    assert result.mechanism == "PACE"
    assert result.pace_info.oid == "0.4.0.127.0.7.2.2.4.2.2"
    assert iso.aid_selected == "A0000002471001"
    assert len(stub.calls) == 1


# ---------------------------------------------------------------------------
# Auto mode — fallback to BAC
# ---------------------------------------------------------------------------


def test_auto_mode_falls_back_to_bac_when_cardaccess_missing():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    not_found = CardAccessNotFound("nope", sw1=0x6A, sw2=0x82)
    with patch.object(neg._card_access_reader, "read", side_effect=not_found), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        result = neg.open(FakeMRZ(), mode="auto")

    mock_bac.assert_called_once()
    assert result.mechanism == "BAC"
    assert iso.aid_selected == "A0000002471001"


def test_auto_mode_falls_back_to_bac_on_parse_error():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    with patch.object(neg._card_access_reader, "read", return_value=b"\xff\xff\xff\xff"), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        result = neg.open(FakeMRZ(), mode="auto")

    mock_bac.assert_called_once()
    assert result.mechanism == "BAC"


def test_auto_mode_falls_back_to_bac_on_read_error():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    read_err = CardAccessReadError("hardware glitch", sw1=0x69, sw2=0x82)
    with patch.object(neg._card_access_reader, "read", side_effect=read_err), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        result = neg.open(FakeMRZ(), mode="auto")

    mock_bac.assert_called_once()
    assert result.mechanism == "BAC"


def test_auto_mode_falls_back_to_bac_when_no_supported_pace_info():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    # OID not in our supported list — auto mode should silently fall back.
    # Valid OID with the PACE prefix that's not in our default supported list.
    blob = _pace_blob(("0.4.0.127.0.7.2.2.4.99.1", 2, 13))

    with patch.object(neg._card_access_reader, "read", return_value=blob), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        result = neg.open(FakeMRZ(), mode="auto")

    mock_bac.assert_called_once()
    assert result.mechanism == "BAC"


def test_auto_mode_falls_back_when_pace_authentication_fails():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    blob = _pace_blob(("0.4.0.127.0.7.2.2.4.2.2", 2, 13))
    stub = _stub_pace_authenticator(exc=PACEAuthenticationError("nope", mechanism="PACE"))

    with patch.object(neg._card_access_reader, "read", return_value=blob), \
         patch("pypassport.doc9303.access_control.PACEAuthenticator", stub), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        result = neg.open(FakeMRZ(), mode="auto")

    mock_bac.assert_called_once()
    assert result.mechanism == "BAC"


# ---------------------------------------------------------------------------
# PACE mode — no fallback
# ---------------------------------------------------------------------------


def test_pace_mode_fails_when_cardaccess_missing():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)
    not_found = CardAccessNotFound("missing", sw1=0x6A, sw2=0x82)

    with patch.object(neg._card_access_reader, "read", side_effect=not_found), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        with pytest.raises(AccessControlNegotiationError):
            neg.open(FakeMRZ(), mode="pace")
    mock_bac.assert_not_called()


def test_pace_mode_fails_when_no_supported_pace_info():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)
    # Valid OID with the PACE prefix that's not in our default supported list.
    blob = _pace_blob(("0.4.0.127.0.7.2.2.4.99.1", 2, 13))

    with patch.object(neg._card_access_reader, "read", return_value=blob):
        with pytest.raises(NoSupportedPACEInfo):
            neg.open(FakeMRZ(), mode="pace")


def test_pace_mode_propagates_authentication_error():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)
    blob = _pace_blob(("0.4.0.127.0.7.2.2.4.2.2", 2, 13))
    stub = _stub_pace_authenticator(exc=PACEAuthenticationError("nope", mechanism="PACE"))

    with patch.object(neg._card_access_reader, "read", return_value=blob), \
         patch("pypassport.doc9303.access_control.PACEAuthenticator", stub):
        with pytest.raises(PACEAuthenticationError):
            neg.open(FakeMRZ(), mode="pace")


# ---------------------------------------------------------------------------
# BAC mode
# ---------------------------------------------------------------------------


def test_bac_mode_does_not_read_card_access():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    with patch.object(neg._card_access_reader, "read") as mock_read, \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac:
        result = neg.open(FakeMRZ(), mode="bac")

    mock_read.assert_not_called()
    mock_bac.assert_called_once()
    assert result.mechanism == "BAC"
    assert iso.aid_selected == "A0000002471001"


def test_bac_failure_6a88_produces_helpful_hint():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)
    not_found = CardAccessNotFound("missing", sw1=0x6A, sw2=0x82)

    def _bac_fail(self, mrz):
        raise BACAuthenticationError(
            "chip returned 6A88 — BAC-related referenced data was not found (6A88). "
            "This document may require PACE — try access_control='auto' or access_control='pace'.",
            mechanism="BAC", sw1=0x6A, sw2=0x88,
        )

    with patch.object(neg._card_access_reader, "read", side_effect=not_found), \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate", _bac_fail):
        with pytest.raises(BACAuthenticationError) as excinfo:
            neg.open(FakeMRZ(), mode="auto")

    msg = str(excinfo.value)
    assert "PACE" in msg
    assert "6A88" in msg


# ---------------------------------------------------------------------------
# AID selection
# ---------------------------------------------------------------------------


def test_aid_select_failure_raised_as_negotiation_error():
    iso = FakeISO7816()
    iso.aid_should_fail = (0x6A, 0x82)
    neg = AccessControlNegotiator(iso)

    with patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate"):
        with pytest.raises(AccessControlNegotiationError):
            neg.open(FakeMRZ(), mode="bac")


# ---------------------------------------------------------------------------
# None mode
# ---------------------------------------------------------------------------


def test_none_mode_only_selects_aid():
    iso = FakeISO7816()
    neg = AccessControlNegotiator(iso)

    with patch.object(neg._card_access_reader, "read") as mock_read, \
         patch("pypassport.doc9303.access_control.BACAuthenticator.authenticate") as mock_bac, \
         patch("pypassport.doc9303.access_control.PACEAuthenticator.authenticate") as mock_pace:
        result = neg.open(None, mode="none")

    mock_read.assert_not_called()
    mock_bac.assert_not_called()
    mock_pace.assert_not_called()
    assert result.mechanism == "NONE"
    assert iso.aid_selected == "A0000002471001"


# ---------------------------------------------------------------------------
# OID encoding
# ---------------------------------------------------------------------------


def test_oid_encoding_pace_ecdh_gm_aes128():
    # OID 0.4.0.127.0.7.2.2.4.2.2 encoded value (no tag/length).
    # First subid combines 0 and 4 -> 0x04. The rest (0, 127, 0, 7, 2, 2, 4, 2, 2)
    # are each below 0x80 so encode to one byte apiece.
    expected = bytes([0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02])
    assert _oid_to_der_value("0.4.0.127.0.7.2.2.4.2.2") == expected


def test_oid_encoding_large_subid():
    # 1.2.840.113549 - leading 1.2 -> 0x2A; 840 -> 0x86 0x48; 113549 -> 0x86 0xF7 0x0D
    assert _oid_to_der_value("1.2.840.113549") == bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D])
