from smartcard import util
from pypassport.asn1 import asn1Length
from binascii import unhexlify, hexlify


def toHexString(input, format=util.PACK):
    """
    b"ABC"             -> '414243'
    [0x41, 0x42, 0x43] -> '414243'
    """
    if isinstance(input, bytes):
        input = list(input)
    if isinstance(input, int):
        input = [input]
    return util.toHexString(input, format)


def toBytes(input):
    """
    '414243' -> b"ABC"
    """
    return bytes(util.toBytes(input))


def toList(input):
    """
    '414243' -> [0x41, 0x42, 0x43]
    """
    return util.toBytes(input)


def parseTLV(data):
    if isinstance(data, list):
        data = bytes(data)
    if isinstance(data, str):
        data = toBytes(data)
    assert isinstance(data, bytes)
    
    if (data[0] & 0x0F) == 0x0F:
        tag = toHexString(data[:2])
        offset = 2
    else:
        tag = toHexString([data[0]])
        offset = 1
    
    (len, lensize) = asn1Length(data[offset:])
    offset += lensize

    total_length = offset + len
    value = data[offset:total_length]
    return tag, value, total_length





# For PACE

def long_to_bytearray (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return bytearray(s)


def hex_to_int(b):
    return int(hexlify(b), 16)