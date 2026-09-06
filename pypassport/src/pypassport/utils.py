"""Small binary and BER-TLV helpers used across the protocol stack.

Historically this module delegated basic hex conversion to ``pyscard``.  That
made every offline parser import the platform-specific PC/SC extension even
when no reader was involved.  The packed representation used by pypassport is
simple enough to implement with the standard library, so reader support stays
optional.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal, cast

from pypassport.asn1 import asn1_length

try:
    from smartcard import util as _smartcard_util  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - exercised in a subprocess test
    _smartcard_util = None


PACK = getattr(_smartcard_util, "PACK", 1)


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return bytes.fromhex(value)
    if isinstance(value, int):
        if not 0 <= value <= 0xFF:
            raise ValueError(f"byte value out of range: {value}")
        return bytes([value])
    if isinstance(value, Iterable):
        return bytes(value)
    raise TypeError(f"expected bytes-like, hex string, integer, or iterable of integers, got {type(value).__name__}")


def to_hex_string(value: Any, format: int = PACK) -> str:
    """Return an uppercase packed hex string.

    ``pypassport`` only uses pyscard's packed format internally.  Alternate
    pyscard display formats are still delegated when pyscard is installed so
    existing external callers that pass ``format=...`` keep working.
    """

    raw = _as_bytes(value)
    if format == PACK:
        return raw.hex().upper()
    if _smartcard_util is None:
        raise ValueError("non-packed hex formats require the optional 'pypassport[reader]' extra")
    return cast(str, _smartcard_util.toHexString(list(raw), format))


def to_bytes(value: Any) -> bytes:
    """Convert a packed hex string or bytes-like value to ``bytes``."""

    return _as_bytes(value)


def to_list(value: Any) -> list[int]:
    """Convert a packed hex string or bytes-like value to a byte list."""

    return list(_as_bytes(value))


def parse_tlv(data: bytes | bytearray | memoryview | str | list[int]) -> tuple[str, bytes, int]:
    """Parse one BER-TLV value and return ``(tag, value, bytes_consumed)``."""

    raw = _as_bytes(data)
    if not raw:
        raise ValueError("cannot parse an empty TLV value")

    if (raw[0] & 0x1F) == 0x1F:
        offset = 1
        while offset < len(raw):
            more = raw[offset] & 0x80
            offset += 1
            if not more:
                break
        if raw[offset - 1] & 0x80:
            raise ValueError("truncated multi-byte TLV tag")
        tag = to_hex_string(raw[:offset])
    else:
        tag = to_hex_string(raw[0])
        offset = 1

    if offset >= len(raw):
        raise ValueError("truncated TLV length")
    length, length_size = asn1_length(raw[offset:])
    offset += length_size
    total_length = offset + length
    if total_length > len(raw):
        raise ValueError(f"truncated TLV value: expected {length} bytes, got {len(raw) - offset}")
    return tag, raw[offset:total_length], total_length


def long_to_bytearray(value: int, endianness: Literal["big", "little"] = "big") -> bytearray:
    """Convert an integer to the shortest bytearray in the requested byte order."""

    if value < 0:
        raise ValueError("value must be non-negative")
    if endianness not in {"big", "little"}:
        raise ValueError("endianness must be 'big' or 'little'")

    width = max(1, (value.bit_length() + 7) // 8)
    return bytearray(value.to_bytes(width, endianness))


def hex_to_int(value: bytes | bytearray | memoryview) -> int:
    """Convert a bytes-like value to an integer using big-endian byte order."""

    return int.from_bytes(_as_bytes(value), "big")
