"""
Pytest configuration for pypassport tests.

pyscard requires a platform-level PC/SC service (and on Linux a C extension
that links against libpcsclite). Neither is available in the CI container, so
we inject a thin stub for the ``smartcard`` package tree before any test
module imports pypassport code.
"""

import sys
import types


def _build_smartcard_stub():
    """Register minimal smartcard stubs so pypassport imports succeed."""

    def _to_hex(data, fmt=1):
        if isinstance(data, (bytes, bytearray)):
            return "".join("%02X" % b for b in data)
        if isinstance(data, (list, tuple)):
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
    ]
    for name in submodules:
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)

    util = sys.modules["smartcard.util"]
    util.toHexString = _to_hex
    util.toBytes = _to_bytes
    util.PACK = 1
    util.HEX = 2

    exc_mod = sys.modules["smartcard.Exceptions"]
    if not hasattr(exc_mod, "NoCardException"):
        exc_mod.NoCardException = type("NoCardException", (Exception,), {})

    sys_mod = sys.modules["smartcard.System"]
    if not hasattr(sys_mod, "readers"):
        sys_mod.readers = lambda: []

    pcsc_mod = sys.modules["smartcard.pcsc"]
    if not hasattr(pcsc_mod, "PCSCExceptions"):
        pcsc_mod.PCSCExceptions = types.ModuleType("smartcard.pcsc.PCSCExceptions")
        sys.modules["smartcard.pcsc.PCSCExceptions"] = pcsc_mod.PCSCExceptions


_build_smartcard_stub()
