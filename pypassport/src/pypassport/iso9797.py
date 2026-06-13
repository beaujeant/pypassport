"""ISO/IEC 9797-1 MAC algorithm implementation using 3DES."""

from Crypto.Cipher import DES


def pad(data: bytes, block_size: int = 8) -> bytes:
    """Apply ISO/IEC 9797-1 padding (method 2): append 0x80 then zero bytes
    to reach a multiple of block_size."""
    padding_length = block_size - (len(data) % block_size)
    padding = b'\x80' + b'\x00' * (padding_length - 1)
    return data + padding


def unpad(data: bytes) -> bytes:
    """Remove ISO/IEC 9797-1 padding (method 2): strip trailing 0x00 bytes
    then the 0x80 marker."""
    i = -1
    while data[i] == 0x00:
        i -= 1

    if data[i] == 0x80:
        return data[0:i]
    return data


def mac(key: bytes, msg: bytes) -> bytes:
    """Compute a retail MAC (ISO/IEC 9797-1 algorithm 3) using 3DES.

    Source: PKI for machine readable travel documents offering
            ICC read-only access, Release 1.1, October 01 2004, p46.

    The message must already be padded to a multiple of 8 bytes.
    """
    if not msg:
        raise ValueError("mac() requires a non-empty, padded message")

    size = len(msg) // 8
    iv = b'\x00' * 8
    tdesa = DES.new(key[0:8], DES.MODE_CBC, iv)

    cb = None
    for i in range(size):
        cb = tdesa.encrypt(msg[i * 8:i * 8 + 8])

    tdesb = DES.new(key[8:16], DES.MODE_ECB)
    tdesa = DES.new(key[0:8], DES.MODE_ECB)

    # size >= 1 because msg is non-empty and padded to a multiple of 8, so the
    # loop above always assigned cb.
    assert cb is not None
    res = tdesb.decrypt(cb)
    return tdesa.encrypt(res)
