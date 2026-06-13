"""Tests for the Comparer pane's pure diff helpers (no Tk required)."""

import pytest

from epassportviewer.comparer import parse_hex, diff_summary, _ef_blobs_from_snapshot


def test_parse_hex_tolerates_whitespace_and_prefix():
    assert parse_hex("  41 42\n43 ") == b"ABC"
    assert parse_hex("0x4142") == b"AB"
    assert parse_hex("") == b""


@pytest.mark.parametrize("bad", ["zz", "414"])
def test_parse_hex_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        parse_hex(bad)


def test_identical_blobs():
    s = diff_summary(b"\x01\x02\x03", b"\x01\x02\x03")
    assert s["equal"] is True
    assert s["hamming"] == 0
    assert s["first_diff"] is None
    assert s["length_delta"] == 0


def test_byte_mismatch_is_detected():
    s = diff_summary(b"\x01\x02\x03", b"\x01\xff\x03")
    assert s["equal"] is False
    assert s["hamming"] == 1
    assert s["first_diff"] == 1
    assert s["length_delta"] == 0


def test_length_difference_flagged_after_matching_overlap():
    s = diff_summary(b"\x01\x02", b"\x01\x02\x03\x04")
    assert s["equal"] is False
    assert s["hamming"] == 0          # the overlap matches
    assert s["first_diff"] == 2       # first side runs out here
    assert s["length_delta"] == 2
    assert s["compared"] == 2


def test_mismatch_takes_priority_over_length():
    s = diff_summary(b"\xaa\x02", b"\x01\x02\x03")
    assert s["first_diff"] == 0
    assert s["hamming"] == 1


def test_ef_blobs_from_snapshot_merges_sections():
    snap = {
        "mf_ef_raw": {"EF.COM": "60", "EF.SOD": ""},
        "ef_raw": {"DG1": "61", "DG2": None},
    }
    assert _ef_blobs_from_snapshot(snap) == {"EF.COM": "60", "DG1": "61"}
