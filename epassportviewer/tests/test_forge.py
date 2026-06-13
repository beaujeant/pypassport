"""Round-trip tests for Forge's raw ↔ fielded APDU conversion.

These exercise the pure helpers only; they don't build any Tk widgets, so they
run headless.
"""

import pytest

from epassportviewer.apdu_format import assemble_apdu, parse_apdu


# (label, raw hex) — one example per ISO 7816-4 short APDU case.
_VALID = [
    ("case 1: header only",        "00A40400"),
    ("case 2: Le only",            "00A4020C0C"),
    ("case 3: Lc + data",          "00A4020C023F00"),
    ("case 4: Lc + data + Le",     "00A4020C023F0000"),
    ("get challenge (Le)",         "0084000008"),
    ("internal auth (data + Le)",  "0088000008112233445566778800"),
]


@pytest.mark.parametrize("label, raw", _VALID, ids=[v[0] for v in _VALID])
def test_parse_then_assemble_round_trips(label, raw):
    f = parse_apdu(raw)
    assert assemble_apdu(
        f["cla"], f["ins"], f["p1"], f["p2"], f["lc"], f["data"], f["le"]
    ) == raw.upper()


def test_parse_fields_are_split_correctly():
    f = parse_apdu("00 A4 02 0C 02 3F 00 00")  # spaces tolerated
    assert f == {
        "cla": "00", "ins": "A4", "p1": "02", "p2": "0C",
        "lc": "02", "data": "3F00", "le": "00",
    }


def test_assemble_derives_lc_from_data_when_blank():
    # DATA present, LC blank → LC computed from the data length.
    assert assemble_apdu("00", "A4", "02", "0C", "", "3F00", "") == "00A4020C023F00"


def test_assemble_round_trips_back_to_fields():
    raw = assemble_apdu("00", "A4", "02", "0C", "02", "3F00", "00")
    f = parse_apdu(raw)
    assert (f["cla"], f["ins"], f["p1"], f["p2"], f["lc"], f["data"], f["le"]) == \
        ("00", "A4", "02", "0C", "02", "3F00", "00")


@pytest.mark.parametrize("bad", ["", "00A4", "00A402", "ZZ", "00A4020C0"])
def test_parse_rejects_malformed_input(bad):
    with pytest.raises(ValueError):
        parse_apdu(bad)


def test_parse_rejects_ambiguous_length():
    # Lc says 5 data bytes but only 2 follow.
    with pytest.raises(ValueError):
        parse_apdu("00A4020C05AABB")
