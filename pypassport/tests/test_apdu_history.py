"""Tests for APDUHistory listener registry and mutation helpers.

The serialisation round-trip lives in test_apdu_history_serialisation.py; this
file covers the live-view plumbing the GUI relies on: listeners firing on
record (and surviving a listener that raises), removal, and the delete/clear
mutators with their indexing and length behaviour.
"""

import pytest

from pypassport.apdu_history import APDUHistory, APDUTransaction


@pytest.fixture(autouse=True)
def _clear_history():
    APDUHistory.get().clear()
    yield
    APDUHistory.get().clear()


def _tx(**overrides):
    fields = dict(
        request_cla="00", request_ins="A4", request_p1="02", request_p2="0C",
        request_lc="02", request_data="011E", request_le="",
        response_data="", response_sw1=0x90, response_sw2=0x00,
        sm_active=False, sm_type="", source="tool",
    )
    fields.update(overrides)
    return APDUTransaction(**fields)


# -- listeners --------------------------------------------------------------


def test_listener_fires_on_record_with_the_transaction():
    h = APDUHistory.get()
    seen = []
    h.add_listener(seen.append)

    tx = _tx()
    h.record(tx)

    assert seen == [tx]
    h.remove_listener(seen.append)  # not the same object; no-op, but harmless


def test_remove_listener_stops_callbacks():
    h = APDUHistory.get()
    seen = []

    def cb(tx):
        seen.append(tx)

    h.add_listener(cb)
    h.record(_tx())
    h.remove_listener(cb)
    h.record(_tx())

    assert len(seen) == 1


def test_remove_unknown_listener_is_a_noop():
    h = APDUHistory.get()
    # Removing something never registered must not raise.
    h.remove_listener(lambda tx: None)


def test_record_survives_a_listener_that_raises():
    h = APDUHistory.get()
    calls = []

    def bad(tx):
        raise RuntimeError("listener blew up")

    def good(tx):
        calls.append(tx)

    h.add_listener(bad)
    h.add_listener(good)

    tx = _tx()
    # The exception is swallowed and logged; the good listener still runs and
    # the entry is still recorded.
    h.record(tx)

    assert calls == [tx]
    assert len(h) == 1


# -- delete / clear / indexing ----------------------------------------------


def test_delete_removes_entry_at_index():
    h = APDUHistory.get()
    h.record(_tx(request_ins="A4"))
    h.record(_tx(request_ins="B0"))
    h.record(_tx(request_ins="84"))

    h.delete(1)

    assert len(h) == 2
    assert [t.request_ins for t in h] == ["A4", "84"]


def test_delete_out_of_range_raises_indexerror():
    h = APDUHistory.get()
    h.record(_tx())
    with pytest.raises(IndexError):
        h.delete(5)


def test_clear_empties_history():
    h = APDUHistory.get()
    h.record(_tx())
    h.record(_tx())
    assert len(h) == 2

    h.clear()
    assert len(h) == 0
    assert list(h) == []


def test_getitem_and_iter_snapshot():
    h = APDUHistory.get()
    h.record(_tx(request_ins="A4"))
    h.record(_tx(request_ins="B0"))

    assert h[0].request_ins == "A4"
    assert h[-1].request_ins == "B0"

    # __iter__ yields over a snapshot copy, so mutating during iteration is safe.
    collected = []
    for tx in h:
        collected.append(tx.request_ins)
        if tx.request_ins == "A4":
            h.clear()
    assert collected == ["A4", "B0"]
