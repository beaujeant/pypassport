"""Raw ↔ fielded command-APDU conversion.

Pure string helpers shared by the Forge tab, kept free of any Tk/UI imports so
they can be unit-tested headlessly. Only short-form APDUs (Lc/Le ≤ 255) are
handled, which is all this tool emits.
"""


def parse_apdu(hexstr):
    """Parse a full command APDU hex string into a fields dict.

    Returns ``{"cla","ins","p1","p2","lc","data","le"}`` as uppercase hex
    strings (``lc``/``data``/``le`` may be ""). Raises ``ValueError`` on
    malformed input.
    """
    clean = "".join(hexstr.split()).replace(":", "")
    if len(clean) % 2:
        raise ValueError("Hex string has an odd number of digits.")
    try:
        raw = bytes.fromhex(clean)
    except ValueError:
        raise ValueError("Not a valid hex string.")
    if len(raw) < 4:
        raise ValueError("A command APDU needs at least 4 header bytes (CLA INS P1 P2).")

    fields = {
        "cla": "%02X" % raw[0], "ins": "%02X" % raw[1],
        "p1": "%02X" % raw[2], "p2": "%02X" % raw[3],
        "lc": "", "data": "", "le": "",
    }
    body = raw[4:]
    if len(body) == 0:                      # case 1: header only
        return fields
    if len(body) == 1:                      # case 2: Le only
        fields["le"] = "%02X" % body[0]
        return fields

    n = body[0]                             # candidate Lc
    rest = body[1:]
    if len(rest) == n:                      # case 3: Lc + data
        fields["lc"] = "%02X" % n
        fields["data"] = rest.hex().upper()
    elif len(rest) == n + 1:                # case 4: Lc + data + Le
        fields["lc"] = "%02X" % n
        fields["data"] = rest[:n].hex().upper()
        fields["le"] = "%02X" % rest[n]
    else:
        raise ValueError(
            "Ambiguous APDU: the byte after the header (Lc=%02X) does not match "
            "the %d remaining data byte(s)." % (n, len(rest))
        )
    return fields


def assemble_apdu(cla, ins, p1, p2, lc, data, le):
    """Join APDU fields into one contiguous uppercase hex string.

    Mirrors the send path: when DATA is present but Lc is blank, Lc is derived
    from the data length so the result is a well-formed command APDU.
    """
    cla = cla or "00"
    ins = ins or "00"
    p1 = p1 or "00"
    p2 = p2 or "00"
    lc = lc or ""
    data = data or ""
    le = le or ""
    if data and not lc:
        lc = "%02X" % (len(data) // 2)
    return "".join((cla, ins, p1, p2, lc, data, le)).upper()
