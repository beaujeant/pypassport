"""Deterministic APDU fuzzing and campaign execution helpers.

The GUI uses this module as the transport-level engine for low-level testing:
it generates bounded mutation sets from a seed APDU, runs them through the
existing ISO 7816 channel, and reduces the responses into status/timing
clusters.  The engine is intentionally deterministic so a campaign can be
replayed from an exported JSON result.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from pypassport.iso7816 import APDUCommand, APDUResponse, ISO7816Exception
from pypassport.utils import to_hex_string


STRATEGY_BASELINE = "baseline"
STRATEGY_HEADER_BOUNDARY = "header_boundary"
STRATEGY_CLA_SWEEP = "cla_sweep"
STRATEGY_INS_SWEEP = "ins_sweep"
STRATEGY_P1_SWEEP = "p1_sweep"
STRATEGY_P2_SWEEP = "p2_sweep"
STRATEGY_LE_BOUNDARY = "le_boundary"
STRATEGY_LENGTH_EDGE = "length_edge"
STRATEGY_DATA_BITFLIP = "data_bitflip"
STRATEGY_TLV_LENGTH = "tlv_length"
STRATEGY_PAYLOAD_LENGTH = "payload_length"
STRATEGY_OVERSIZED_PAYLOAD = "oversized_payload"
STRATEGY_EXTENDED_ENCODING = "extended_encoding"
STRATEGY_SFI_SWEEP = "sfi_sweep"
STRATEGY_DATA_WORD_SWEEP = "data_word_sweep"

STRATEGY_LABELS = {
    STRATEGY_HEADER_BOUNDARY: "Header boundaries",
    STRATEGY_CLA_SWEEP: "CLA sweep",
    STRATEGY_INS_SWEEP: "INS sweep",
    STRATEGY_P1_SWEEP: "P1 sweep",
    STRATEGY_P2_SWEEP: "P2 sweep",
    STRATEGY_LE_BOUNDARY: "Le boundaries",
    STRATEGY_LENGTH_EDGE: "Lc/data edge cases",
    STRATEGY_DATA_BITFLIP: "Data bit flips",
    STRATEGY_TLV_LENGTH: "TLV length corruption",
    STRATEGY_PAYLOAD_LENGTH: "Payload lengths",
    STRATEGY_OVERSIZED_PAYLOAD: "Oversized payloads",
    STRATEGY_EXTENDED_ENCODING: "Canonical extended APDUs",
    STRATEGY_SFI_SWEEP: "READ BINARY SFI sweep",
    STRATEGY_DATA_WORD_SWEEP: "Data word sweep",
}

DEFAULT_STRATEGIES = (
    STRATEGY_HEADER_BOUNDARY,
    STRATEGY_LE_BOUNDARY,
    STRATEGY_LENGTH_EDGE,
    STRATEGY_DATA_BITFLIP,
    STRATEGY_TLV_LENGTH,
)

# These instructions can change chip state, retry counters, or file content.
# Sweep generators omit them unless the caller explicitly enables them.
STATE_CHANGING_INS = {
    0x20,  # VERIFY
    0x24,  # CHANGE REFERENCE DATA
    0x2C,  # RESET RETRY COUNTER
    0x44,  # REHABILITATE
    0xD6,  # UPDATE BINARY
    0xDA,  # ERASE BINARY
    0xDC,  # UPDATE / ERASE RECORDS
    0xE2,  # APPEND RECORD
    0xD0,  # WRITE BINARY
    0xD2,  # WRITE RECORD
    0xDB,  # PUT DATA
    0xDD,  # UPDATE / ERASE RECORDS (odd instruction)
    0x46,  # GENERATE ASYMMETRIC KEY PAIR
    0xE0,  # CREATE FILE
    0xE4,  # DELETE FILE
    0xE6,  # TERMINATE DF
    0xFE,  # TERMINATE CARD USAGE / proprietary lifecycle operation
}

# Positive allowlist used for INS mutations under the safe fuzz profile.
# Unknown proprietary instructions cannot be assumed to be read-only.
SAFE_INS = {
    0x70,  # MANAGE CHANNEL (transient)
    0x84,  # GET CHALLENGE
    0x88,  # INTERNAL AUTHENTICATE
    0xA4,  # SELECT
    0xB0,  # READ BINARY
    0xB1,  # READ BINARY (odd instruction)
    0xB2,  # READ RECORD
    0xB3,  # READ RECORD (odd instruction)
    0xC0,  # GET RESPONSE
    0xCA,  # GET DATA
    0xCB,  # GET DATA (odd instruction)
}

_BYTE_BOUNDARIES = (0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF)
_LE_BOUNDARIES = ("", "00", "01", "02", "07", "08", "0F", "10", "7F", "80", "FE", "FF")
_PAYLOAD_LENGTHS = (0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255)
_OVERSIZED_PAYLOAD_LENGTHS = (256, 257, 511, 512, 1024)
_PAYLOAD_PATTERNS = (0x00, 0x41, 0xFF)


@dataclass(frozen=True)
class FuzzCase:
    """One deterministic APDU mutation."""

    case_id: int
    family: str
    mutation: str
    cla: str
    ins: str
    p1: str
    p2: str
    lc: str
    data: str
    le: str
    extended: bool | None = None

    @property
    def raw_hex(self) -> str:
        return str(self.to_command()).upper()

    def to_command(self) -> APDUCommand:
        return APDUCommand(self.cla, self.ins, self.p1, self.p2, self.lc, self.data, self.le, extended=self.extended)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"raw_hex": self.raw_hex}


@dataclass
class FuzzResult:
    """Observed result for one fuzz case execution."""

    case: FuzzCase
    repeat_index: int
    elapsed_ms: float
    response_data: str = ""
    sw1: int | None = None
    sw2: int | None = None
    status: str = ""
    classification: str = ""
    error: str = ""
    interesting: bool = False
    divergent: bool = False
    security_signal: str = ""
    response_authenticated: bool | None = None

    @property
    def status_word(self) -> str:
        if self.sw1 is None or self.sw2 is None:
            return ""
        return f"{self.sw1:02X}{self.sw2:02X}"

    @property
    def response_hex(self) -> str:
        return f"{self.response_data}{self.status_word}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.to_dict(),
            "repeat_index": self.repeat_index,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "response_data": self.response_data,
            "response_hex": self.response_hex,
            "sw1": self.sw1,
            "sw2": self.sw2,
            "status_word": self.status_word,
            "status": self.status,
            "classification": self.classification,
            "error": self.error,
            "interesting": self.interesting,
            "divergent": self.divergent,
            "security_signal": self.security_signal,
            "response_authenticated": self.response_authenticated,
        }


def is_state_changing_instruction(ins: str | int) -> bool:
    """Return whether *ins* is excluded from safe sweeps by default."""

    try:
        value = int(ins, 16) if isinstance(ins, str) else int(ins)
    except (TypeError, ValueError):
        return False
    return value in STATE_CHANGING_INS


def generate_fuzz_cases(
    seed: APDUCommand,
    strategies: Iterable[str] = DEFAULT_STRATEGIES,
    *,
    max_cases: int = 256,
    include_state_changing: bool = False,
) -> list[FuzzCase]:
    """Generate a bounded, deduplicated mutation set from *seed*.

    The seed is always emitted as case 1.  ``max_cases`` caps the result before
    expensive sweeps such as INS or 16-bit data-word discovery can run away.
    """

    if max_cases < 1:
        return []
    selected = set(strategies)
    fields = _fields(seed)
    cases: list[FuzzCase] = []
    seen: set[str] = set()

    def add(family: str, mutation: str, **updates: str) -> bool:
        candidate = {**fields, **updates}
        raw_hex = _raw_hex(candidate)
        if raw_hex in seen:
            return len(cases) < max_cases
        seen.add(raw_hex)
        cases.append(FuzzCase(len(cases) + 1, family, mutation, **candidate))
        return len(cases) < max_cases

    add(STRATEGY_BASELINE, "baseline")
    if len(cases) >= max_cases:
        return cases

    if STRATEGY_HEADER_BOUNDARY in selected:
        for field in ("cla", "ins", "p1", "p2"):
            for value in _BYTE_BOUNDARIES:
                if field == "ins" and not include_state_changing and value not in SAFE_INS:
                    continue
                if not add(STRATEGY_HEADER_BOUNDARY, f"{field.upper()}={value:02X}", **{field: f"{value:02X}"}):
                    return cases

    for strategy, field in (
        (STRATEGY_CLA_SWEEP, "cla"),
        (STRATEGY_INS_SWEEP, "ins"),
        (STRATEGY_P1_SWEEP, "p1"),
        (STRATEGY_P2_SWEEP, "p2"),
    ):
        if strategy not in selected:
            continue
        for value in range(256):
            if field == "ins" and not include_state_changing and value not in SAFE_INS:
                continue
            if not add(strategy, f"{field.upper()}={value:02X}", **{field: f"{value:02X}"}):
                return cases

    if STRATEGY_LE_BOUNDARY in selected:
        for le_value in _LE_BOUNDARIES:
            label = le_value or "absent"
            if not add(STRATEGY_LE_BOUNDARY, f"Le={label}", le=le_value):
                return cases

    if STRATEGY_LENGTH_EDGE in selected:
        data_len = len(fields["data"]) // 2
        values = {0, 1, max(data_len - 1, 0), data_len, min(data_len + 1, 255), 0x7F, 0x80, 0xFE, 0xFF}
        for value in sorted(values):
            if not add(STRATEGY_LENGTH_EDGE, f"Lc={value:02X} with original data", lc=f"{value:02X}"):
                return cases
        mutations = (
            ("drop data keep Lc", ""),
            ("truncate last data byte", fields["data"][:-2]),
            ("append 00", fields["data"] + "00"),
            ("append FF", fields["data"] + "FF"),
            ("append 16x41", fields["data"] + "41" * 16),
        )
        for label, mutated_data in mutations:
            if not add(STRATEGY_LENGTH_EDGE, label, data=mutated_data):
                return cases

    if STRATEGY_DATA_BITFLIP in selected:
        data_bytes = bytearray.fromhex(fields["data"])
        if not data_bytes:
            for value in _BYTE_BOUNDARIES:
                if not add(STRATEGY_DATA_BITFLIP, f"inject {value:02X}", lc="01", data=f"{value:02X}"):
                    return cases
        else:
            positions = sorted({0, len(data_bytes) // 2, len(data_bytes) - 1})
            for position in positions:
                for mask in (0x01, 0x80, 0xFF):
                    mutated = bytearray(data_bytes)
                    mutated[position] ^= mask
                    if not add(
                        STRATEGY_DATA_BITFLIP,
                        f"data[{position}] xor {mask:02X}",
                        data=mutated.hex().upper(),
                    ):
                        return cases

    if STRATEGY_TLV_LENGTH in selected:
        tlv_data = bytearray.fromhex(fields["data"])
        length_index = _first_tlv_length_index(tlv_data)
        if length_index is not None:
            for value in _BYTE_BOUNDARIES:
                mutated = bytearray(tlv_data)
                mutated[length_index] = value
                if not add(
                    STRATEGY_TLV_LENGTH,
                    f"TLV length byte[{length_index}]={value:02X}",
                    data=mutated.hex().upper(),
                ):
                    return cases

    if STRATEGY_PAYLOAD_LENGTH in selected:
        for length in _PAYLOAD_LENGTHS:
            for pattern in _PAYLOAD_PATTERNS:
                payload = bytes([pattern]) * length
                if not add(
                    STRATEGY_PAYLOAD_LENGTH,
                    f"payload len={length} pattern={pattern:02X}",
                    lc=f"{length:02X}" if length else "",
                    data=payload.hex().upper(),
                ):
                    return cases

    if STRATEGY_OVERSIZED_PAYLOAD in selected:
        for length in _OVERSIZED_PAYLOAD_LENGTHS:
            for pattern in _PAYLOAD_PATTERNS:
                payload = bytes([pattern]) * length
                if not add(
                    STRATEGY_OVERSIZED_PAYLOAD,
                    f"payload len={length} wrapped Lc={length & 0xFF:02X} pattern={pattern:02X}",
                    lc=f"{length & 0xFF:02X}",
                    data=payload.hex().upper(),
                    extended=False,
                ):
                    return cases

    if STRATEGY_EXTENDED_ENCODING in selected:
        for length in (256, 512, 1024):
            payload = bytes([0x41]) * length
            if not add(STRATEGY_EXTENDED_ENCODING, f"case 4E payload len={length}", lc=f"{length:04X}",
                       data=payload.hex().upper(), le="0000", extended=True):
                return cases

    if STRATEGY_SFI_SWEEP in selected:
        for sfi in range(1, 32):
            if not add(STRATEGY_SFI_SWEEP, f"SFI={sfi:02X}", p1=f"{0x80 | sfi:02X}"):
                return cases

    if STRATEGY_DATA_WORD_SWEEP in selected:
        data = fields["data"]
        tail = data[4:] if len(data) >= 4 else ""
        for value in range(0x10000):
            if not add(
                STRATEGY_DATA_WORD_SWEEP,
                f"data[0:2]={value:04X}",
                data=f"{value:04X}{tail}",
                lc=f"{(len(tail) // 2) + 2:02X}",
            ):
                return cases

    return cases


def run_fuzz_campaign(
    iso7816: Any,
    cases: Iterable[FuzzCase],
    *,
    channel: str = "current",
    repeat_each: int = 1,
    delay_ms: int = 0,
    reset_policy: str = "never",
    reset_callback: Callable[[], None] | None = None,
    stop_event: threading.Event | None = None,
    on_result: Callable[[FuzzResult], None] | None = None,
    source: str = "fuzz",
) -> list[FuzzResult]:
    """Execute a mutation campaign against an ISO7816-like channel."""

    repeat_each = max(1, int(repeat_each))
    delay_ms = max(0, int(delay_ms))
    results: list[FuzzResult] = []
    if reset_policy == "before_campaign" and reset_callback is not None:
        reset_callback()

    for case in cases:
        for repeat_index in range(1, repeat_each + 1):
            if stop_event is not None and stop_event.is_set():
                _mark_interesting(results)
                return results
            if reset_policy == "before_each" and reset_callback is not None:
                reset_callback()

            result = _execute_case(iso7816, case, repeat_index, channel=channel, source=source)
            results.append(result)
            if on_result is not None:
                on_result(result)

            if reset_policy == "on_error" and result.error and reset_callback is not None:
                reset_callback()
            if delay_ms:
                if stop_event is not None:
                    if stop_event.wait(delay_ms / 1000.0):
                        _mark_interesting(results)
                        return results
                else:
                    time.sleep(delay_ms / 1000.0)

    _mark_interesting(results)
    return results


def summarize_fuzz_results(results: Iterable[FuzzResult]) -> dict[str, Any]:
    """Return response/status/timing clusters for a completed campaign."""

    items = list(results)
    if not items:
        return {
            "total": 0,
            "status_counts": {},
            "classification_counts": {},
            "error_count": 0,
            "interesting_count": 0,
        }
    _mark_interesting(items)
    timings = [item.elapsed_ms for item in items]
    return {
        "total": len(items),
        "status_counts": dict(Counter(item.status_word or "ERROR" for item in items)),
        "classification_counts": dict(Counter(item.classification for item in items)),
        "error_count": sum(1 for item in items if item.error),
        "interesting_count": sum(1 for item in items if item.interesting),
        "divergent_count": sum(1 for item in items if item.divergent),
        "security_signal_counts": dict(Counter(item.security_signal for item in items if item.security_signal)),
        "timing_ms": {
            "min": round(min(timings), 3),
            "median": round(statistics.median(timings), 3),
            "max": round(max(timings), 3),
        },
        "slowest": [
            {
                "case_id": item.case.case_id,
                "mutation": item.case.mutation,
                "elapsed_ms": round(item.elapsed_ms, 3),
                "status_word": item.status_word,
            }
            for item in sorted(items, key=lambda item: item.elapsed_ms, reverse=True)[:5]
        ],
    }


def classify_response(sw1: int | None, sw2: int | None, *, error: str = "") -> str:
    """Return a stable coarse class for response clustering."""

    if error:
        return "transport-error"
    if sw1 is None or sw2 is None:
        return "no-response"
    if (sw1, sw2) == (0x90, 0x00):
        return "success"
    if sw1 == 0x61:
        return "more-data"
    if sw1 == 0x6C:
        return "length-hint"
    if sw1 in (0x62, 0x63):
        return "warning"
    if sw1 == 0x69:
        return "security"
    if sw1 in (0x67, 0x6A, 0x6B):
        return "input-rejected"
    if sw1 in (0x6D, 0x6E):
        return "unsupported"
    return "other"


def _fields(command: APDUCommand) -> dict[str, Any]:
    return {
        "cla": command.cla.upper(),
        "ins": command.ins.upper(),
        "p1": command.p1.upper(),
        "p2": command.p2.upper(),
        "lc": command.lc.upper(),
        "data": command.data.upper(),
        "le": command.le.upper(),
        "extended": command.extended,
    }


def _raw_hex(fields: dict[str, Any]) -> str:
    return str(APDUCommand(**fields)).upper()


def _first_tlv_length_index(data: bytearray) -> int | None:
    if len(data) < 2:
        return None
    index = 1
    if data[0] & 0x1F == 0x1F:
        while index < len(data) and data[index] & 0x80:
            index += 1
        index += 1
    return index if index < len(data) else None


def _execute_case(iso7816: Any, case: FuzzCase, repeat_index: int, *, channel: str, source: str) -> FuzzResult:
    saved_ciphering = getattr(iso7816, "ciphering", None)
    if channel == "plaintext":
        iso7816.ciphering = None
    started = time.perf_counter()
    try:
        if channel == "wire":
            response = iso7816.transmit_raw(case.raw_hex, source=source)
        else:
            response = iso7816.transmit(
                case.to_command(),
                f"Fuzz {case.family}: {case.mutation}",
                full=True,
                source=source,
            )
        elapsed_ms = (time.perf_counter() - started) * 1000
        data = to_hex_string(response.data) if response.data else ""
        return FuzzResult(
            case=case,
            repeat_index=repeat_index,
            elapsed_ms=elapsed_ms,
            response_data=data,
            sw1=response.sw1,
            sw2=response.sw2,
            status=APDUResponse.describe(response.sw1, response.sw2),
            classification=classify_response(response.sw1, response.sw2),
            response_authenticated=getattr(response, "authenticated", None),
        )
    except ISO7816Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        sw1 = getattr(exc, "sw1", None)
        sw2 = getattr(exc, "sw2", None)
        return FuzzResult(
            case=case,
            repeat_index=repeat_index,
            elapsed_ms=elapsed_ms,
            sw1=sw1,
            sw2=sw2,
            status=APDUResponse.describe(sw1, sw2) if sw1 is not None and sw2 is not None else "",
            classification=classify_response(sw1, sw2, error=str(exc)),
            error=str(exc),
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return FuzzResult(
            case=case,
            repeat_index=repeat_index,
            elapsed_ms=elapsed_ms,
            classification=classify_response(None, None, error=str(exc)),
            error=str(exc),
        )
    finally:
        if channel == "plaintext":
            iso7816.ciphering = saved_ciphering


def _mark_interesting(results: list[FuzzResult]) -> None:
    if not results:
        return
    baseline = results[0]
    baseline_signature = (baseline.status_word, baseline.response_data, baseline.error)
    timings = [item.elapsed_ms for item in results]
    median = statistics.median(timings)
    slow_threshold = max(median * 3, median + 50.0)
    for item in results:
        signature = (item.status_word, item.response_data, item.error)
        item.divergent = signature != baseline_signature
        if item.error:
            item.security_signal = "transport-failure"
        elif item.response_data and not baseline.response_data:
            item.security_signal = "unexpected-data"
        elif item.status_word == "9000" and baseline.status_word != "9000":
            item.security_signal = "access-control-bypass"
        elif item.response_authenticated is False and item.response_data:
            item.security_signal = "unauthenticated-data"
        elif baseline.status_word == "9000" and item.status_word != "9000":
            item.security_signal = "semantic-differential"
        elif item.elapsed_ms >= slow_threshold:
            item.security_signal = "timing-outlier"
        else:
            item.security_signal = ""
        item.interesting = bool(item.security_signal)
