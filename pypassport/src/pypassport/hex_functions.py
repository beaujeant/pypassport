"""Utility functions for converting between binary, hex-string, integer, and list representations."""


# bin to something

def binToHex(val) -> int:
    """Convert a binary string to an integer.

    '\xaa\xbb' --> 43707
    """
    return int(binToHexRep(val), 16)


def binToHexRep(data) -> str:
    """Convert a binary string to a lowercase hex string.

    b'\xaa\xbb' --> 'aabb'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if isinstance(data, int):
        data = bytes([data])
    return data.hex()


def binToHexList(data) -> list:
    """Convert a binary string to a list of integers.

    b'\xaa\xbb' --> [0xAA, 0xBB]
    """
    return hexRepToList(binToHexRep(data))


# hex to something

def hexToBin(data) -> bytes:
    """Convert an integer to its binary representation.

    511 --> b'\x01\xff'
    """
    return hexRepToBin("%x" % data)


def hexToHexRep(data) -> str:
    """Convert a single hex integer to its uppercase two-char hex string."""
    return hexListToHexRep([data])


def hexToHexList(string: str) -> list:
    """Convert a hex string of two-char groups to a list of integers."""
    n = 0
    out = []
    while n < len(string):
        out.append(int(string[n:n + 2], 16))
        n += 2
    return out


# hexRep to something

def hexRepToBin(hexrep) -> bytes:
    """Convert a hex string to bytes.

    'aabb' --> b'\xaa\xbb'
    """
    if not isinstance(hexrep, str):
        hexrep = hexrep.decode("utf-8")
    if len(hexrep) % 2:
        hexrep = "0" + hexrep
    return bytes.fromhex(hexrep)


def hexRepToList(string: str) -> list:
    """Convert a hex string to a list of integers.

    'AABBCC' --> [170, 187, 204]
    """
    n = 0
    out = []
    while n < len(string):
        out.append(int(string[n:n + 2], 16))
        n += 2
    return out


def hexRepToHex(string: str) -> int:
    """Convert a hex string to an integer."""
    return binToHex(hexRepToBin(string))


def listToHexRep(data) -> str:
    """Convert a list of integers to an uppercase hex string.

    [170, 187, 204] --> 'AABBCC'
    """
    out = []
    for item in data:
        out.append('%02X' % int(item))
    return ''.join(out)


# hexList to something

def hexListToBin(data) -> bytes:
    """Convert a list of hex integers to bytes.

    [0xAA, 0xBB] --> b'\xaa\xbb'
    """
    return hexRepToBin(hexListToHexRep(data))


def hexListToHex(data) -> int:
    """Convert a list of hex integers to an integer.

    [0xAA, 0xBB] --> 43707
    """
    return binToHex(hexListToBin(data))


def hexListToHexRep(data) -> str:
    """Convert a list of hex integers to an uppercase hex string.

    [0xAA, 0xBB] --> 'AABB'
    """
    out = ''
    for d in data:
        out += '%02X' % int(d)
    return out


def intToBin(data) -> bytes:
    """Convert an integer to its binary (bytes) representation.

    13 --> b'\r'
    """
    return hexRepToBin("%x" % int(data))


def intToHexRep(data: int, size: int = 2) -> str:
    """Convert an integer to an uppercase hex string of the given digit width.

    56 --> '38'
    """
    mask = "%0" + str(size) + "x"
    return (mask % data).upper()


def intToHexList(data: int) -> list:
    """Convert an integer to a list of byte values."""
    return binToHexList(intToBin(data))
