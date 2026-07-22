"""Canonical ICAO Doc 9303 file identifier conversion helpers.

The protocol stack needs to move between a small set of identifiers: logical
data-group names, EF names, FIDs, BER tags, parser classes, and the numeric
SOD hash index.  Older versions exposed a generic table converter with several
display and third-party dump formats.  Keeping only protocol-relevant
identifiers makes the accepted input space explicit and avoids stringly-typed
format selection in callers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _FileIdentifier:
    dg: str
    ef: str
    fid: str
    tag: str
    class_name: str
    sod_index: str


_FILES = (
    _FileIdentifier("COM", "EF.COM", "011E", "60", "Common", "EF"),
    _FileIdentifier("DG1", "EF.DG1", "0101", "61", "DataGroup1", "1"),
    _FileIdentifier("DG2", "EF.DG2", "0102", "75", "DataGroup2", "2"),
    _FileIdentifier("DG3", "EF.DG3", "0103", "63", "DataGroup3", "3"),
    _FileIdentifier("DG4", "EF.DG4", "0104", "76", "DataGroup4", "4"),
    _FileIdentifier("DG5", "EF.DG5", "0105", "65", "DataGroup5", "5"),
    _FileIdentifier("DG6", "EF.DG6", "0106", "66", "DataGroup6", "6"),
    _FileIdentifier("DG7", "EF.DG7", "0107", "67", "DataGroup7", "7"),
    _FileIdentifier("DG8", "EF.DG8", "0108", "68", "DataGroup8", "8"),
    _FileIdentifier("DG9", "EF.DG9", "0109", "69", "DataGroup9", "9"),
    _FileIdentifier("DG10", "EF.DG10", "010A", "6A", "DataGroup10", "10"),
    _FileIdentifier("DG11", "EF.DG11", "010B", "6B", "DataGroup11", "11"),
    _FileIdentifier("DG12", "EF.DG12", "010C", "6C", "DataGroup12", "12"),
    _FileIdentifier("DG13", "EF.DG13", "010D", "6D", "DataGroup13", "13"),
    _FileIdentifier("DG14", "EF.DG14", "010E", "6E", "DataGroup14", "14"),
    _FileIdentifier("DG15", "EF.DG15", "010F", "6F", "DataGroup15", "15"),
    _FileIdentifier("DG16", "EF.DG16", "0110", "70", "DataGroup16", "16"),
    _FileIdentifier("SOD", "EF.SOD", "011D", "77", "SOD", "SOD"),
    _FileIdentifier("ATR/INFO", "EF.ATR", "2F01", "ATR/INFO", "ATR", "ATR/INFO"),
    _FileIdentifier("DIR", "EF.DIR", "2F00", "DIR", "DIR", "DIR"),
    _FileIdentifier("CardAccess", "EF.CardAccess", "011C", "42", "CardAccess", "CardAccess"),
    _FileIdentifier("CardSecurity", "EF.CardSecurity", "011D", "77", "CardSecurity", "CardSecurity"),
)


def _lookup(data: object) -> _FileIdentifier:
    key = str(data).upper()
    for identifier in _FILES:
        values = (
            identifier.dg,
            identifier.ef,
            identifier.fid,
            identifier.tag,
            identifier.sod_index,
        )
        if any(key == value.upper() for value in values):
            return identifier
    raise KeyError(f"Invalid data group: {data}")


def to_dg(data: object) -> str:
    """Return the canonical logical data-group name for *data*."""

    return _lookup(data).dg


def to_ef(data: object) -> str:
    """Return the canonical EF name for *data*."""

    return _lookup(data).ef


def to_fid(data: object) -> str:
    """Return the EF file identifier for *data*."""

    return _lookup(data).fid


def to_tag(data: object) -> str:
    """Return the BER-TLV tag for *data*."""

    return _lookup(data).tag


def to_class(data: object) -> str:
    """Return the parser class name associated with *data*."""

    return _lookup(data).class_name


def to_other(data: object) -> str:
    """Return the EF.SOD data-group hash index for *data*."""

    return _lookup(data).sod_index
