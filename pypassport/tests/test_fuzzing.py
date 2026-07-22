from pypassport.fuzzing import (
    STRATEGY_DATA_WORD_SWEEP,
    STRATEGY_INS_SWEEP,
    STRATEGY_LENGTH_EDGE,
    STRATEGY_OVERSIZED_PAYLOAD,
    classify_response,
    generate_fuzz_cases,
    run_fuzz_campaign,
    summarize_fuzz_results,
)
from pypassport.iso7816 import APDUCommand, APDUResponse


class FakeISO7816:
    def __init__(self):
        self.ciphering = object()
        self.sent = []

    def transmit(self, command, _label, *, full=False, source=None):
        self.sent.append((str(command), self.ciphering, source))
        if command.ins == "84":
            return APDUResponse([], 0x90, 0x00)
        return APDUResponse([], 0x6D, 0x00)


def test_ins_sweep_skips_state_changing_instructions_by_default():
    seed = APDUCommand("00", "84", "00", "00", le="08")
    cases = generate_fuzz_cases(seed, [STRATEGY_INS_SWEEP], max_cases=300)
    instructions = {case.ins for case in cases}

    assert "20" not in instructions
    assert "24" not in instructions
    assert "D6" not in instructions
    assert "84" in instructions


def test_length_edges_preserve_malformed_lc_data_combinations():
    seed = APDUCommand("00", "A4", "02", "0C", "02", "3F00", "")
    cases = generate_fuzz_cases(seed, [STRATEGY_LENGTH_EDGE], max_cases=64)

    assert any(case.lc == "FF" and case.data == "3F00" for case in cases)
    assert any(case.mutation == "drop data keep Lc" and case.raw_hex == "00A4020C02" for case in cases)


def test_data_word_sweep_is_bounded_by_max_cases():
    seed = APDUCommand("00", "A4", "02", "0C", "02", "011E", "")
    cases = generate_fuzz_cases(seed, [STRATEGY_DATA_WORD_SWEEP], max_cases=4)

    assert [case.raw_hex for case in cases] == [
        "00A4020C02011E",
        "00A4020C020000",
        "00A4020C020001",
        "00A4020C020002",
    ]


def test_oversized_payloads_wrap_short_lc_but_keep_full_data():
    seed = APDUCommand("00", "86", "00", "00", "02", "7C00", "00")
    cases = generate_fuzz_cases(seed, [STRATEGY_OVERSIZED_PAYLOAD], max_cases=2)

    oversized = cases[1]
    assert oversized.lc == "00"
    assert len(oversized.data) // 2 == 256
    assert len(oversized.raw_hex) // 2 == 4 + 1 + 256 + 1


def test_campaign_restores_ciphering_after_plaintext_send_and_marks_differences():
    iso = FakeISO7816()
    cases = generate_fuzz_cases(APDUCommand("00", "84", "00", "00", le="08"), [STRATEGY_INS_SWEEP], max_cases=2)
    results = run_fuzz_campaign(iso, cases, channel="plaintext")
    summary = summarize_fuzz_results(results)

    assert all(ciphering is None for _, ciphering, _ in iso.sent)
    assert iso.ciphering is not None
    assert results[0].status_word == "9000"
    assert results[1].status_word == "6D00"
    assert results[1].interesting is True
    assert summary["status_counts"] == {"9000": 1, "6D00": 1}


def test_response_classification():
    assert classify_response(0x90, 0x00) == "success"
    assert classify_response(0x69, 0x82) == "security"
    assert classify_response(0x6C, 0x10) == "length-hint"
    assert classify_response(None, None, error="timeout") == "transport-error"
