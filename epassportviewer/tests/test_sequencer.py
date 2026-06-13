"""Tests for the Sequencer pane's pure randomness helpers (no Tk required)."""

import math

from epassportviewer.sequencer import shannon_entropy, randomness_stats, format_report


def test_shannon_entropy_extremes():
    assert shannon_entropy([]) == 0.0
    assert shannon_entropy([7, 7, 7, 7]) == 0.0          # no uncertainty
    assert shannon_entropy([0, 1]) == 1.0                # one fair bit
    # Four equiprobable symbols → 2 bits.
    assert math.isclose(shannon_entropy([0, 1, 2, 3]), 2.0)


def test_randomness_stats_counts_duplicates():
    challenges = [b"\x00\x01", b"\x00\x01", b"\x02\x03"]
    stats = randomness_stats(challenges)
    assert stats["total"] == 3
    assert stats["unique"] == 2
    assert stats["duplicates"] == 1
    assert stats["nonce_len"] == 2


def test_histogram_counts_every_byte():
    challenges = [b"\x00\x00", b"\xff\xff"]
    stats = randomness_stats(challenges)
    assert stats["byte_histogram"][0x00] == 2
    assert stats["byte_histogram"][0xFF] == 2
    assert sum(stats["byte_histogram"]) == 4


def test_position_entropy_per_column():
    # Position 0 is constant (entropy 0); position 1 is a fair bit (entropy 1).
    challenges = [b"\x00\x00", b"\x00\x01"]
    stats = randomness_stats(challenges)
    assert stats["position_entropy"][0] == 0.0
    assert stats["position_entropy"][1] == 1.0


def test_short_nonce_does_not_break_position_analysis():
    # A stray short response shrinks nonce_len rather than crashing.
    stats = randomness_stats([b"\x01\x02\x03", b"\x04\x05"])
    assert stats["nonce_len"] == 2
    assert len(stats["position_entropy"]) == 2


def test_format_report_runs_and_mentions_key_stats():
    report = format_report(randomness_stats([b"\x00\x01", b"\x02\x03"]))
    assert "Nonces collected : 2" in report
    assert "Duplicate nonces : 0" in report
    assert "byte[0]" in report
