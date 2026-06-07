"""
Read EF.CardAccess from an eMRTD chip.

EF.CardAccess (FID 0x011C) is a transparent EF located under the Master
File. It carries the SecurityInfos blob used by the terminal to discover
PACE support before any access-control mechanism has been established.

Reading does not require BAC/PACE: EF.CardAccess is freely readable.
"""

import logging

from pypassport.asn1 import asn1Length
from pypassport.iso7816 import APDUCommand, ISO7816Exception


# FID of EF.CardAccess as defined in ICAO 9303 Part 11.
EF_CARD_ACCESS_FID = "011C"
MASTER_FILE_FID = "3F00"


class CardAccessNotFound(Exception):
    """
    EF.CardAccess could not be selected — the chip does not advertise PACE.
    Callers in auto mode should fall back to BAC; callers in pace mode
    should propagate this as a hard failure.
    """

    def __init__(self, message, sw1=None, sw2=None):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2


class CardAccessReadError(Exception):
    """Raised on an I/O failure reading EF.CardAccess (post-select)."""

    def __init__(self, message, sw1=None, sw2=None):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2


class CardAccessReader:
    """Select and read EF.CardAccess as raw DER bytes."""

    # Maximum Le for a single READ BINARY in short-Le mode. The chip is
    # free to return fewer bytes (we use ISO 7816 short reads).
    _MAX_LE = 0xDF

    def __init__(self, iso7816):
        self._iso7816 = iso7816

    def read(self) -> bytes:
        """
        Select the Master File, select EF.CardAccess, and read it out.

        :return: The raw DER-encoded SecurityInfos blob.
        :raise CardAccessNotFound: If the file cannot be located. The
            exception's sw1/sw2 attributes carry the chip's status word.
        :raise CardAccessReadError: If selection succeeds but reading fails.
        """
        # Selecting the Master File is optional on most chips, but some
        # require it before they will resolve a FID under the MF. We try
        # it first and ignore failures — if the chip rejects MF select we
        # may still be able to select EF.CardAccess from the current DF.
        try:
            self._select_master_file()
        except ISO7816Exception as exc:
            logging.debug(
                "Select MF before EF.CardAccess returned %02X%02X; continuing.",
                exc.sw1 or 0, exc.sw2 or 0,
            )

        try:
            self._iso7816.selectElementaryFile(EF_CARD_ACCESS_FID)
        except ISO7816Exception as exc:
            # 6A82 (file not found) and 6A86 (incorrect P1/P2) both indicate
            # the chip does not expose EF.CardAccess — treat as "no PACE".
            raise CardAccessNotFound(
                f"EF.CardAccess (FID {EF_CARD_ACCESS_FID}) could not be selected "
                f"(SW={(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X}: {exc.data}).",
                sw1=exc.sw1, sw2=exc.sw2,
            ) from exc

        return self._read_all()

    def _select_master_file(self):
        # 00 A4 00 0C 02 3F 00 — select MF by FID, no FCI returned.
        toSend = APDUCommand("00", "A4", "00", "0C", data=MASTER_FILE_FID)
        self._iso7816.transmit(toSend, "Select Master File")

    def _read_all(self) -> bytes:
        # Read 4 bytes to discover the ASN.1 length, then iterate.
        try:
            header = self._iso7816.readBinary(0, 4)
        except ISO7816Exception as exc:
            raise CardAccessReadError(
                f"Could not read EF.CardAccess header "
                f"(SW={(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X}: {exc.data}).",
                sw1=exc.sw1, sw2=exc.sw2,
            ) from exc

        if len(header) < 2:
            raise CardAccessReadError(
                "EF.CardAccess is too short to contain a SecurityInfos blob."
            )

        # SecurityInfos is a SET, but EF.CardAccess can in principle wrap
        # any ASN.1 type starting with a single-byte tag. Parse the length
        # field using the same helper as the data-group reader.
        try:
            body_len, len_size = asn1Length(header[1:])
        except Exception as exc:
            raise CardAccessReadError(f"Invalid ASN.1 length in EF.CardAccess: {exc}") from exc

        total = 1 + len_size + body_len
        out = bytes(header[:min(total, 4)])

        # Read the rest in MAX_LE chunks.
        offset = len(out)
        while offset < total:
            to_read = min(total - offset, self._MAX_LE)
            try:
                chunk = self._iso7816.readBinary(offset, to_read)
            except ISO7816Exception as exc:
                raise CardAccessReadError(
                    f"EF.CardAccess read failed at offset {offset} "
                    f"(SW={(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X}: {exc.data}).",
                    sw1=exc.sw1, sw2=exc.sw2,
                ) from exc
            if not chunk:
                break
            out += bytes(chunk)
            offset += len(chunk)

        return out
