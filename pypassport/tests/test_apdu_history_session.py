"""Tests for serialising the APDU history to/from a saved research session.

``APDUHistory.to_list`` renders every transaction as a JSON-friendly dict and
``from_list`` parses them back, restoring timestamps and (optionally) retagging
the source so an imported session is distinct from a live capture.
"""

import json
from datetime import datetime

import pytest

from pypassport.apdu_history import APDUHistory, APDUTransaction


@pytest.fixture(autouse=True)
def _clear_history():
    APDUHistory.get().clear()
    yield
    APDUHistory.get().clear()


def _sample(**overrides):
    base = dict(
        request_cla="00",
        request_ins="A4",
        request_p1="02",
        request_p2="0C",
        request_lc="02",
        request_data="011E",
        request_le="",
        response_data="",
        response_sw1=0x90,
        response_sw2=0x00,
        sm_active=True,
        sm_type="AES",
        source="tool",
        wire_request_hex="0CA4020C048702CAFE00",
        wire_response_hex="870201AB990290008E02CCDD9000",
        comment="select EF.COM",
        color="#ffd6d6",
    )
    base.update(overrides)
    return APDUTransaction(**base)


def test_to_list_is_json_serialisable_with_iso_timestamp():
    hist = APDUHistory.get()
    tx = _sample()
    hist.record(tx)

    items = hist.to_list()
    assert len(items) == 1
    # The timestamp is rendered as an ISO 8601 string, not a datetime object.
    assert items[0]["timestamp"] == tx.timestamp.isoformat()
    # The whole list survives a JSON round-trip unchanged.
    assert json.loads(json.dumps(items)) == items


def test_round_trip_preserves_every_field():
    hist = APDUHistory.get()
    hist.record(_sample())
    hist.record(_sample(request_ins="B0", comment="", color="", source="forge"))

    items = json.loads(json.dumps(hist.to_list()))
    hist.from_list(items)

    assert len(hist) == 2
    first, second = hist[0], hist[1]
    assert first.request_ins == "A4"
    assert first.comment == "select EF.COM"
    assert first.color == "#ffd6d6"
    assert first.wire_request_hex == "0CA4020C048702CAFE00"
    assert first.sm_active is True and first.sm_type == "AES"
    assert isinstance(first.timestamp, datetime)
    # Sources are preserved when no override is requested.
    assert first.source == "tool" and second.source == "forge"


def test_from_list_overrides_source():
    hist = APDUHistory.get()
    hist.record(_sample(source="tool"))
    hist.record(_sample(source="forge"))

    hist.from_list(hist.to_list(), source="imported")

    assert [tx.source for tx in hist] == ["imported", "imported"]


def test_from_list_replaces_existing_entries():
    hist = APDUHistory.get()
    hist.record(_sample(comment="live"))
    assert len(hist) == 1

    hist.from_list([], source="imported")
    assert len(hist) == 0


def test_from_list_skips_malformed_records():
    hist = APDUHistory.get()
    good = _sample().__dict__.copy()
    good["timestamp"] = _sample().timestamp.isoformat()

    items = [
        good,
        "not a dict",  # wrong type — skipped
        {"request_cla": "00"},  # missing required fields — skipped
        {**good, "unknown_field": "junk"},  # extra key — ignored, still loads
    ]
    hist.from_list(items)

    # Only the two well-formed records survive; the unknown key was dropped.
    assert len(hist) == 2
    assert all(not hasattr(tx, "unknown_field") for tx in hist)


def test_from_list_tolerates_bad_timestamp():
    hist = APDUHistory.get()
    item = _sample().__dict__.copy()
    item["timestamp"] = "not-a-timestamp"

    hist.from_list([item])

    assert len(hist) == 1
    assert isinstance(hist[0].timestamp, datetime)
