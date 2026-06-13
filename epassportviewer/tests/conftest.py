"""Pytest configuration for ePassportViewer tests.

Importing the viewer's panes pulls in pypassport, which imports pyscard. That
needs a platform PC/SC service (and a C extension) unavailable in CI, so we
register the same thin ``smartcard`` stub the pypassport test-suite uses before
any viewer module is imported.
"""

import sys
import types


def _build_smartcard_stub():
    def _to_hex(data, fmt=1):
        if isinstance(data, (bytes, bytearray, list, tuple)):
            return "".join("%02X" % b for b in data)
        if isinstance(data, int):
            return "%02X" % data
        return str(data)

    def _to_bytes(s):
        if not s:
            return []
        try:
            return list(bytes.fromhex(s.replace(" ", "")))
        except Exception:
            return []

    submodules = [
        "smartcard",
        "smartcard.System",
        "smartcard.util",
        "smartcard.Exceptions",
        "smartcard.pcsc",
        "smartcard.pcsc.PCSCExceptions",
        "smartcard.scard",
        "smartcard.CardType",
        "smartcard.CardRequest",
    ]
    for name in submodules:
        if name not in sys.modules:
            mod = types.ModuleType(name)
            # Give the top-level package a __path__ so "smartcard.X" reads as a
            # package import rather than "smartcard is not a package".
            if name == "smartcard":
                mod.__path__ = []  # type: ignore[attr-defined]
            sys.modules[name] = mod

    util = sys.modules["smartcard.util"]
    util.toHexString = _to_hex
    util.toBytes = _to_bytes
    util.PACK = 1
    util.HEX = 2

    exc_mod = sys.modules["smartcard.Exceptions"]
    for exc in ("NoCardException", "CardConnectionException"):
        if not hasattr(exc_mod, exc):
            setattr(exc_mod, exc, type(exc, (Exception,), {}))

    sys_mod = sys.modules["smartcard.System"]
    if not hasattr(sys_mod, "readers"):
        sys_mod.readers = lambda: []

    pcsc_mod = sys.modules["smartcard.pcsc"]
    if not hasattr(pcsc_mod, "PCSCExceptions"):
        pcsc_mod.PCSCExceptions = types.ModuleType("smartcard.pcsc.PCSCExceptions")
        sys.modules["smartcard.pcsc.PCSCExceptions"] = pcsc_mod.PCSCExceptions

    cardtype_mod = sys.modules["smartcard.CardType"]
    if not hasattr(cardtype_mod, "AnyCardType"):
        cardtype_mod.AnyCardType = type("AnyCardType", (), {})

    cardreq_mod = sys.modules["smartcard.CardRequest"]
    if not hasattr(cardreq_mod, "CardRequest"):
        cardreq_mod.CardRequest = type("CardRequest", (), {})


_build_smartcard_stub()
