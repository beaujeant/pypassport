"""Application-context file discovery and bounded transparent-EF reads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pypassport.doc9303.file_context import EMRTD, MF, FileReference, enumerate_files
from pypassport.iso7816 import ISO7816Exception
from pypassport.utils import parse_tlv


@dataclass(frozen=True)
class FileProbe:
    application: str
    fid: str
    sfi: int | None
    logical_name: str | None
    selected: bool
    fci: bytes
    sw: str
    control: dict[str, Any] | None = None


def _find_tlv(data, wanted):
    output, offset = [], 0
    while offset < len(data):
        try:
            tag, value, used = parse_tlv(data[offset:])
        except Exception:
            break
        if tag == wanted:
            output.append(value)
        # Constructed bit is in the first tag octet.
        if bytes.fromhex(tag)[0] & 0x20:
            output.extend(_find_tlv(value, wanted))
        offset += used
    return output


def parse_file_control(data):
    """Parse useful FCI/FCP/FMD attributes without discarding unknown TLVs."""
    names = {"80": "file_size", "81": "total_file_size", "82": "file_descriptor",
             "83": "fid", "84": "df_name", "88": "sfi", "8A": "life_cycle_status",
             "8C": "compact_security_attributes", "86": "security_attributes", "8B": "security_environment"}
    parsed = {"raw_hex": bytes(data).hex().upper(), "objects": {}}

    def walk(value):
        offset = 0
        while offset < len(value):
            tag, child, used = parse_tlv(value[offset:])
            parsed["objects"][names.get(tag, tag)] = child.hex().upper()
            if tag in ("80", "81"):
                parsed[names[tag]] = int.from_bytes(child, "big")
            if bytes.fromhex(tag)[0] & 0x20:
                walk(child)
            offset += used
    try:
        walk(bytes(data))
    except Exception as exc:
        parsed["parse_error"] = str(exc)
    return parsed


class FileSystemExplorer:
    def __init__(self, iso7816):
        self.iso7816 = iso7816

    def applications(self):
        """List AIDs advertised by EF.DIR plus the ICAO eMRTD AID."""
        aids = {EMRTD}
        try:
            self.iso7816.select_master_file()
            self.iso7816.select_elementary_file("2F00")
            raw = self.iso7816.read_selected_binary_all(chunk_size=256, maximum=65536)
            aids.update(value.hex().upper() for value in _find_tlv(raw, "4F"))
        except Exception:
            pass
        return sorted(aids)

    def enumerate(self, application=EMRTD, *, extra_fids=()):
        """Probe known and explicit FIDs without conflating other DFs."""
        refs = list(enumerate_files(application))
        refs.extend(FileReference(f"{application}:{fid}", f"EF.{fid}", application,
                                  str(fid).upper(), None, None, "ElementaryFile") for fid in extra_fids)
        if application == MF:
            self.iso7816.select_master_file()
        else:
            self.iso7816.select_dedicated_file(application)
        probes = []
        for ref in refs:
            try:
                fci = self.iso7816.select_file("02", "00", ref.fid)
                probes.append(FileProbe(application, ref.fid, ref.sfi, ref.name, True, bytes(fci), "9000", parse_file_control(fci)))
            except ISO7816Exception as exc:
                probes.append(FileProbe(application, ref.fid, ref.sfi, ref.name, False, b"",
                                        f"{(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X}"))
        return probes

    def read_file(self, application, fid, *, sfi=None, maximum=1024 * 1024):
        """Read one explicit application/FID without relying on ambiguous tags."""

        fid = str(fid).upper()
        if len(fid) != 4 or any(character not in "0123456789ABCDEF" for character in fid):
            raise ValueError("FID must contain exactly four hexadecimal characters")
        from pypassport.doc9303.data_group import read_elementary_file

        reference = FileReference(
            f"{str(application).upper()}:{fid}",
            f"EF.{fid}",
            str(application).upper(),
            fid,
            sfi,
            None,
            "ElementaryFile",
        )
        return read_elementary_file(reference, self.iso7816, max_file_size=maximum)
