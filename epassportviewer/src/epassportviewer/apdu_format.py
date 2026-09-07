"""Raw ↔ fielded command-APDU conversion.

Pure string helpers shared by the Forge tab, kept free of any Tk/UI imports so
they can be unit-tested headlessly. Canonical short and extended APDUs are
handled; the separate raw path intentionally preserves malformed encodings.
"""

from pypassport.doc9303 import converter
from pypassport.iso7816 import APDUCommand

_INS_NAMES = {
    "20": "VERIFY",
    "22": "MANAGE SECURITY ENVIRONMENT",
    "24": "CHANGE REFERENCE DATA",
    "2C": "RESET RETRY COUNTER",
    "82": "EXTERNAL AUTHENTICATE",
    "84": "GET CHALLENGE",
    "86": "GENERAL AUTHENTICATE",
    "88": "INTERNAL AUTHENTICATE",
    "A4": "SELECT FILE",
    "B0": "READ BINARY",
    "B2": "READ RECORDS",
    "C0": "GET RESPONSE",
    "CA": "GET DATA",
    "D6": "UPDATE BINARY",
    "DA": "ERASE BINARY",
    "DC": "UPDATE RECORDS",
    "E2": "APPEND RECORD",
}


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

    try:
        command = APDUCommand.from_bytes(raw)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    return {name: getattr(command, name) for name in ("cla", "ins", "p1", "p2", "lc", "data", "le")}


def parse_apdu_lenient(hexstr):
    """Split a malformed short APDU without normalising its raw bytes.

    This is used by Forge when an analyst intentionally wants to send a
    length-inconsistent command. Valid APDUs should go through
    :func:`parse_apdu`; on malformed input this fallback treats the first body
    byte as Lc and preserves every remaining byte as DATA.
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
        "cla": "%02X" % raw[0],
        "ins": "%02X" % raw[1],
        "p1": "%02X" % raw[2],
        "p2": "%02X" % raw[3],
        "lc": "",
        "data": "",
        "le": "",
    }
    body = raw[4:]
    if body:
        fields["lc"] = "%02X" % body[0]
        fields["data"] = body[1:].hex().upper()
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
    return str(APDUCommand(cla, ins, p1, p2, lc, data, le)).upper()


def describe_apdu_fields(cla, ins, p1, p2, lc="", data="", le=""):
    """Return a compact human-readable label for one command APDU."""

    cla = (cla or "00").upper()
    ins = (ins or "00").upper()
    p1 = (p1 or "00").upper()
    p2 = (p2 or "00").upper()
    data = (data or "").upper()
    name = _INS_NAMES.get(ins, f"INS {ins}")

    if ins == "A4" and data:
        if data == "3F00":
            return "SELECT FILE (MF)"
        if data == "A0000002471001":
            return "SELECT FILE (eMRTD AID)"
        try:
            return f"SELECT FILE ({converter.to_ef(data)})"
        except KeyError:
            return f"SELECT FILE ({data})"

    if ins == "B0":
        try:
            if int(p1, 16) & 0x80:
                return f"READ BINARY (SFID {int(p1, 16) & 0x1F:02X}, offset {int(p2, 16)})"
            return f"READ BINARY (offset {int(p1 + p2, 16)})"
        except ValueError:
            return name

    if data:
        return f"{name} ({len(data) // 2} data bytes)"
    if le:
        return f"{name} (Le={le.upper()})"
    return name


def describe_apdu(hexstr):
    """Parse and describe a raw command APDU string."""

    fields = parse_apdu(hexstr)
    return describe_apdu_fields(**fields)
