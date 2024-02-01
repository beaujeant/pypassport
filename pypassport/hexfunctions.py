def binToHex(val):
    """'\xaa\xbb' --> 4307"""
    return int(binToHexRep(val), 16)


def binToHexRep(data):
    """'\xaa\xbb' --> 'aabb'"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if isinstance(data, int):
        data = bytes([data])
    return data.hex()


def binToHexList(data):
    """'\xaa\xbb' --> [0xAA, 0xBB]"""
    return hexRepToList(binToHexRep(data))


#hex to something

def hexToBin(data):
    """511 --> '\x00\x00\x00\x00\x00\x00\x01\xff'"""
    return hexRepToBin("%x" % data)


def hexToHexRep(data):
    return hexListToHexRep([data])


def hexToHexList(string):
    # translate string of 2 char HEX to int list
    n = 0
    out = []
    while n < len(string):
        out.append(int(string[n:n + 2], 16))
        n += 2
    return out


#hexRep to something

def hexRepToBin(hexrep):
    if not isinstance(hexrep, str):
        hexrep = hexrep.decode("utf-8")
    if len(hexrep) % 2:
        hexrep = "0" + hexrep
    return bytes.fromhex(hexrep)


def hexRepToList(string):
    """'AABBCC' --> [170, 187, 204]"""
    n = 0
    out = []
    while n < len(string):
        out.append(int(string[n:n + 2], 16))
        n += 2
    return out


def hexRepToHex(string):
    return binToHex(hexRepToBin(string))


def listToHexRep(list):
    """[170, 187, 204] --> 'AABBCC'"""
    out = []
    for item in list:
        out.append('%02X' % int(item))
    return out.upper()


#hexList to something

def hexListToBin(data):
    """[0xAA, 0xBB] -> '\xaa\xbb'"""
    hexRep = hexListToHexRep(data)
    return hexRepToBin(hexRep)


def hexListToHex(data):
    """[0xAA, 0xBB] --> 43707"""
    bin = hexListToBin(data)
    return binToHex(bin)


def hexListToHexRep(data):
    """[0xAA, 0xBB] -> 'AABB4"""
    out = ''
    for d in data:
        out += '%02X' % int(d)
    return out


def intToBin(data):
    """13 -> d"""
    return hexRepToBin("%x" % int(data))


def intToHexRep(data, size=2):
    """56 -> 38"""
    mask = "%0" + str(size) + "x"
    return (mask % data).upper()


def intToHexList(data):
    return binToHexList(intToBin(data))
