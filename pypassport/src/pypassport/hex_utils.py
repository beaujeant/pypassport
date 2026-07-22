"""Utility functions for converting between binary, hex-string, and integer representations."""

from __future__ import annotations

from typing import Union


def bin_to_hex(val: Union[bytes, bytearray, memoryview, str, int]) -> int:
    """Convert a binary string to an integer.

    b'\xaa\xbb' --> 43707
    """
    return int(bin_to_hex_rep(val), 16)


def bin_to_hex_rep(data: Union[bytes, bytearray, memoryview, str, int]) -> str:
    """Convert a binary string to a lowercase hex string.

    b'\xaa\xbb' --> 'aabb'
    """
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, int):
        if not 0 <= data <= 0xFF:
            raise ValueError(f"byte value out of range: {data}")
        raw = bytes([data])
    elif isinstance(data, memoryview):
        raw = data.tobytes()
    else:
        raw = bytes(data)
    return raw.hex()


def hex_to_bin(data: int) -> bytes:
    """Convert an integer to its binary representation.

    511 --> b'\x01\xff'
    """
    if data < 0:
        raise ValueError("data must be non-negative")
    return hex_rep_to_bin(f"{data:x}")


def hex_rep_to_bin(hexrep: Union[str, bytes, bytearray, memoryview]) -> bytes:
    """Convert a hex string to bytes.

    'aabb' --> b'\xaa\xbb'
    """
    if not isinstance(hexrep, str):
        hexrep = bytes(hexrep).decode("utf-8")
    if len(hexrep) % 2:
        hexrep = "0" + hexrep
    return bytes.fromhex(hexrep)
