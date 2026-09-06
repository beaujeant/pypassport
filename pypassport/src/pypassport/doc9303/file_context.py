"""Context-aware ICAO/eID file-system identifiers.

FIDs and outer TLV tags are only unique inside a selected application/DF.
In particular EF.SOD and EF.CardSecurity both use 011D/77. This module is
the canonical source of identity for reads and security workflows.
"""

from __future__ import annotations

from dataclasses import dataclass

MF = "MF"
EMRTD = "A0000002471001"


@dataclass(frozen=True)
class FileReference:
    name: str
    ef_name: str
    application: str
    fid: str
    sfi: int | None
    tag: str | None
    parser: str
    sod_index: int | None = None


_DG_TAGS = (0, 0x61, 0x75, 0x63, 0x76, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70)
FILES = (
    FileReference("COM", "EF.COM", EMRTD, "011E", 0x1E, "60", "Common"),
    *tuple(
        FileReference(f"DG{i}", f"EF.DG{i}", EMRTD, f"{0x100 + i:04X}", i, f"{_DG_TAGS[i]:02X}", f"DataGroup{i}", i)
        for i in range(1, 17)
    ),
    FileReference("SOD", "EF.SOD", EMRTD, "011D", 0x1D, "77", "SOD"),
    FileReference("CardAccess", "EF.CardAccess", MF, "011C", 0x1C, "42", "CardAccess"),
    FileReference("CardSecurity", "EF.CardSecurity", MF, "011D", 0x1D, "77", "CardSecurity"),
    FileReference("DIR", "EF.DIR", MF, "2F00", 0x1E, "61", "DIR"),
    FileReference("ATR/INFO", "EF.ATR/INFO", MF, "2F01", 0x1D, None, "ATR"),
    FileReference("CVCA", "EF.CVCA", EMRTD, "011C", 0x1C, "42", "CVCA"),
)


def resolve_file(value, *, application: str | None = None) -> FileReference:
    if isinstance(value, FileReference):
        return value
    key = str(value).upper()
    matches = [
        ref for ref in FILES
        if key in (ref.name.upper(), ref.ef_name.upper(), ref.fid, (ref.tag or "").upper())
        and (application is None or ref.application.upper() == application.upper())
    ]
    named = [ref for ref in matches if key in (ref.name.upper(), ref.ef_name.upper())]
    if len(named) == 1:
        return named[0]
    if len(matches) == 1:
        return matches[0]
    if matches:
        choices = ", ".join(f"{x.name}@{x.application}" for x in matches)
        raise KeyError(f"Ambiguous file identifier {value!r}; specify one of {choices}")
    raise KeyError(f"Unknown file identifier {value!r}")


def enumerate_files(application: str | None = None) -> tuple[FileReference, ...]:
    return tuple(ref for ref in FILES if application is None or ref.application == application)
