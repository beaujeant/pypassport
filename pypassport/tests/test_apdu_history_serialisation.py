"""Tests for APDUHistory.to_list()/from_list() session round-trips.

A saved research session stores the full APDU history (cleartext + wire bytes +
annotations + source + timestamps). These checks lock in that the serialised
form is JSON-friendly and reconstructs faithfully, that imported records are
relabelled source="imported" by default, and that malformed records are skipped
rather than aborting the whole load.
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


def _sample_tx(**overrides):
    fields = dict(
        request_cla="00", request_ins="A4", request_p1="02", request_p2="0C",
        request_lc="02", request_data="011E", request_le="",
        response_data="", response_sw1=0x90, response_sw2=0x00,
        sm_active=True, sm_type="AES", source="tool",
        wire_request_hex="0CA4020C", wire_response_hex="990290008E08",
        comment="select EF.COM", color="#ffd6d6",
    )
    fields.update(overrides)
    return APDUTransaction(**fields)


def test_to_list_is_json_serialisable_with_iso_timestamp():
    h = APDUHistory.get()
    tx = _sample_tx()
    h.record(tx)

    serial = h.to_list()
    assert isinstance(serial, list) and len(serial) == 1
    # timestamp is rendered as an ISO-8601 string, so the whole list survives
    # a json.dumps round-trip.
    assert serial[0]["timestamp"] == tx.timestamp.isoformat()
    json.dumps(serial)


def test_round_trip_preserves_all_fields_and_relabels_source():
    h = APDUHistory.get()
    original = _sample_tx()
    h.record(original)
    serial = json.loads(json.dumps(h.to_list()))

    h.from_list(serial)
    restored = list(h)
    assert len(restored) == 1
    r = restored[0]

    # Every annotation, wire and cleartext field comes back intact.
    assert r.request_data == original.request_data
    assert r.response_sw1 == 0x90 and r.response_sw2 == 0x00
    assert r.sm_active is True and r.sm_type == "AES"
    assert r.wire_request_hex == "0CA4020C"
    assert r.wire_response_hex == "990290008E08"
    assert r.comment == "select EF.COM" and r.color == "#ffd6d6"
    assert isinstance(r.timestamp, datetime)
    assert r.timestamp == original.timestamp
    # ...but the source is relabelled so imported rows are distinct from live.
    assert r.source == "imported"


def test_from_list_can_preserve_original_source():
    h = APDUHistory.get()
    h.record(_sample_tx(source="forge"))
    serial = json.loads(json.dumps(h.to_list()))

    h.from_list(serial, source=None)
    assert list(h)[0].source == "forge"


def test_from_list_replaces_existing_history():
    h = APDUHistory.get()
    h.record(_sample_tx())
    h.record(_sample_tx())
    assert len(h) == 2

    h.from_list([])
    assert len(h) == 0


def test_from_list_skips_malformed_records():
    h = APDUHistory.get()
    # Build a valid serialised record alongside a junk one.
    h.record(_sample_tx())
    good = h.to_list()
    h.clear()

    h.from_list([{"nonsense": 1}, good[0]])
    assert len(h) == 1


def test_from_list_tolerates_bad_or_missing_timestamp():
    h = APDUHistory.get()
    h.record(_sample_tx())
    serial = h.to_list()
    serial[0]["timestamp"] = "not-a-real-timestamp"
    h.from_list(serial)
    assert isinstance(list(h)[0].timestamp, datetime)

    serial[0].pop("timestamp")
    h.from_list(serial)
    assert isinstance(list(h)[0].timestamp, datetime)


def test_from_list_ignores_unknown_keys():
    h = APDUHistory.get()
    h.record(_sample_tx())
    serial = h.to_list()
    serial[0]["future_field"] = "ignored"
    h.from_list(serial)
    assert len(h) == 1
