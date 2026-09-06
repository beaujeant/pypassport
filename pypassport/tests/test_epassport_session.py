"""Shared-session behaviour for L{EPassport}.

The application keeps a single passport object alive across its tabs so that
reading a passport once serves every action: cached data groups are reused and
the Secure Messaging channel stays live. These tests pin the contract that
makes that safe — C{ensure_open} must not re-run PACE/BAC when a channel is
already in place, and a lazy read must bootstrap access control (auto-detecting
PACE vs BAC) when it is not.
"""

from unittest.mock import MagicMock

from pypassport.epassport import EPassport
from pypassport.doc9303.access_control import MODE_AUTO, NegotiationResult
from pypassport.iso7816 import ISO7816Exception


class _BareEP(EPassport):
    """An EPassport with the card-touching constructor skipped."""

    def __init__(self):
        self.iso7816 = MagicMock()
        self.iso7816.ciphering = None
        self._mrz = None
        self._can = None
        self._ac_mode = MODE_AUTO
        self._access_control = None


def test_ensure_open_reuses_live_session(monkeypatch):
    """With Secure Messaging already live, ensure_open returns the previous
    result and never re-runs access control."""
    ep = _BareEP()
    ep.iso7816.ciphering = object()  # SM channel already in place
    sentinel = NegotiationResult(mechanism="PACE")
    ep._access_control = sentinel

    calls = []
    monkeypatch.setattr(ep, "open", lambda *a, **k: calls.append((a, k)))

    result = ep.ensure_open()

    assert result is sentinel
    assert calls == [], "ensure_open must not redo PACE/BAC when SM is live"


def test_ensure_open_opens_with_stored_credentials(monkeypatch):
    """Without a channel, ensure_open falls back to open(), defaulting the mode
    and CAN to whatever the session was last opened/initialised with."""
    ep = _BareEP()
    ep.iso7816.ciphering = None
    ep._ac_mode = MODE_AUTO
    ep._can = "654321"

    captured = {}

    def fake_open(mrz=None, access_control=MODE_AUTO, can=None):
        captured.update(mrz=mrz, access_control=access_control, can=can)
        return NegotiationResult(mechanism="BAC")

    monkeypatch.setattr(ep, "open", fake_open)

    result = ep.ensure_open()

    assert result.mechanism == "BAC"
    assert captured["access_control"] == MODE_AUTO
    assert captured["can"] == "654321"


def test_ensure_open_reopens_when_channel_dropped(monkeypatch):
    """A torn-down channel (e.g. a card reset elsewhere) must re-open even
    though a stale NegotiationResult is still recorded."""
    ep = _BareEP()
    ep.iso7816.ciphering = None  # channel gone
    ep._access_control = NegotiationResult("PACE")  # stale leftover

    calls = []

    def fake_open(*a, **k):
        calls.append(True)
        return NegotiationResult(mechanism="BAC")

    monkeypatch.setattr(ep, "open", fake_open)

    ep.ensure_open()

    assert calls, "ensure_open must re-open when the SM channel is no longer live"


def test_read_bootstraps_access_control_on_6982(monkeypatch):
    """An unauthenticated read that the chip refuses with 6982 must bootstrap
    access control once (via ensure_open) and then retry the read."""
    import pypassport.epassport as epmod

    ep = _BareEP()
    ep.iso7816.ciphering = None

    fake_dg = object()
    reads = {"n": 0}

    def fake_read(tag, iso):
        reads["n"] += 1
        if reads["n"] == 1:
            raise ISO7816Exception("Security status not satisfied", 0x69, 0x82)
        return fake_dg

    monkeypatch.setattr(epmod, "read_elementary_file", fake_read)

    opens = {"n": 0}

    def fake_ensure_open():
        opens["n"] += 1
        ep.iso7816.ciphering = object()  # SM now established

    monkeypatch.setattr(ep, "ensure_open", fake_ensure_open)

    result = ep._read("DG1")

    assert result is fake_dg
    assert opens["n"] == 1, "the 6982 path must bootstrap access control once"
    assert reads["n"] == 2, "the read must be retried once SM is in place"


def test_read_does_not_bootstrap_when_sm_active(monkeypatch):
    """If a channel is already live, a chip error is reported (read returns
    None) rather than triggering a redundant access-control run."""
    import pypassport.epassport as epmod

    ep = _BareEP()
    ep.iso7816.ciphering = object()  # SM active

    def fake_read(tag, iso):
        raise ISO7816Exception("Secure messaging not supported", 0x68, 0x82)

    monkeypatch.setattr(epmod, "read_elementary_file", fake_read)

    called = []
    monkeypatch.setattr(ep, "ensure_open", lambda *a, **k: called.append(True))

    assert ep._read("DG1") is None
    assert called == [], "no bootstrap should run while SM is already active"


def test_card_access_read_restores_emrtd_context_before_later_dg(monkeypatch):
    """Reading MF-level EF.CardAccess must not strand an open session in the MF."""
    import pypassport.epassport as epmod

    class FakeDG:
        def __init__(self, tag):
            self.tag = tag

    ep = _BareEP()
    ep._emrtd_selected = True
    ep.iso7816.selected_context = "emrtd"
    ep.iso7816.select_dedicated_file = lambda aid: setattr(ep.iso7816, "selected_context", "emrtd")

    def fake_read(tag, iso):
        logical = getattr(tag, "name", tag)
        if logical == "CardAccess":
            iso.selected_context = "mf"
            return FakeDG("42")
        if logical == "DG11":
            if iso.selected_context != "emrtd":
                raise ISO7816Exception("File not found", 0x6A, 0x82)
            return FakeDG("6B")
        raise AssertionError(f"unexpected tag {tag}")

    monkeypatch.setattr(epmod, "read_elementary_file", fake_read)

    assert ep["CardAccess"].tag == "42"
    assert ep.iso7816.selected_context == "emrtd"
    assert ep["DG11"].tag == "6B"
