from __future__ import annotations

import logging
from typing import Protocol

from pypassport import reader
from pypassport.apdu_history import APDUHistory, APDUTransaction
from pypassport.interceptor import Interceptor
from pypassport.utils import to_bytes, to_hex_string, to_list


class APDUCommand:
    Instructions = {
        "VERIFY": 0x20,
        "CHANGE REFERENCE DATA": 0x24,
        "RESET RETRY COUNTER": 0x2C,
        "GET CHALLENGE": 0x84,
        "INTERNAL AUTHENTICATE": 0x88,
        "EXTERNAL AUTHENTICATE": 0x82,
        "SELECT FILE": 0xA4,
        "READ BINARY": 0xB0,
        "READ RECORDS": 0xB2,
        "UPDATE BINARY": 0xD6,
        "ERASE BINARY": 0xDA,
        "ERASE RECORDS": 0xDC,
        "UPDATE RECORDS": 0xDC,
        "APPEND RECORD": 0xE2,
    }

    def __init__(self, cla="00", ins="00", p1="00", p2="00", lc="", data="", le="", *, extended=None):
        if isinstance(cla, str):
            self.cla = cla[:2]
        elif isinstance(cla, bytes):
            self.cla = to_hex_string(cla)[:2]
        elif isinstance(cla, int):
            self.cla = to_hex_string([cla])[:2]
        else:
            self.cla = "00"

        if isinstance(ins, str):
            self.ins = ins[:2]
        elif isinstance(ins, bytes):
            self.ins = to_hex_string(ins)[:2]
        elif isinstance(ins, int):
            self.ins = to_hex_string([ins])[:2]
        else:
            self.ins = "00"

        if isinstance(p1, str):
            self.p1 = p1[:2]
        elif isinstance(p1, bytes):
            self.p1 = to_hex_string(p1)[:2]
        elif isinstance(p1, int):
            self.p1 = to_hex_string([p1])[:2]
        else:
            self.p1 = "00"

        if isinstance(p2, str):
            self.p2 = p2[:2]
        elif isinstance(p2, bytes):
            self.p2 = to_hex_string(p2)[:2]
        elif isinstance(p2, int):
            self.p2 = to_hex_string([p2])[:2]
        else:
            self.p2 = "00"

        if isinstance(data, str):
            self.data = "".join(data.split()).upper()
        elif isinstance(data, bytes):
            self.data = to_hex_string(data)
        else:
            self.data = ""

        raw_lc = "".join(lc.split()).upper() if isinstance(lc, str) else (to_hex_string(lc) if isinstance(lc, bytes) else "")
        raw_le = "".join(le.split()).upper() if isinstance(le, str) else (to_hex_string(le) if isinstance(le, bytes) else "")
        data_len = len(self.data) // 2
        if extended is None:
            extended = len(raw_lc) > 2 or len(raw_le) > 2 or data_len > 0xFF or (isinstance(lc, int) and lc > 0xFF) or (isinstance(le, int) and le > 0x100)
        self.extended = bool(extended)

        width = 4 if self.extended else 2
        if raw_lc:
            self.lc = raw_lc[:width].zfill(width)
        elif isinstance(lc, int):
            if not 0 <= lc <= (0xFFFF if self.extended else 0xFF):
                raise ValueError("Lc is outside the selected APDU encoding")
            self.lc = f"{lc:0{width}X}"
        elif self.data:
            if data_len > (0xFFFF if self.extended else 0xFF):
                raise ValueError("APDU data is too long")
            self.lc = f"{data_len:0{width}X}"
        else:
            self.lc = ""

        if raw_le:
            self.le = raw_le[:width].zfill(width)
        elif isinstance(le, int):
            maximum = 0x10000 if self.extended else 0x100
            if not 1 <= le <= maximum:
                raise ValueError("Le is outside the selected APDU encoding")
            encoded_le = 0 if le == maximum else le
            self.le = f"{encoded_le:0{width}X}"
        else:
            self.le = ""

        if len(self.data) % 2:
            raise ValueError("APDU data must contain complete hexadecimal bytes")
        try:
            bytes.fromhex(str(self))
        except ValueError as exc:
            raise ValueError("APDU fields must be hexadecimal") from exc

    def raw(self):
        return to_list(str(self))

    def __str__(self):
        header = self.cla + self.ins + self.p1 + self.p2
        if not self.extended:
            return header + self.lc + self.data + self.le
        # ISO 7816-4 extended cases carry an encoding marker before either
        # the two-byte Le (case 2E) or the two-byte Lc (cases 3E/4E).
        return header + "00" + self.lc + self.data + self.le

    @classmethod
    def from_bytes(cls, encoded):
        """Parse and validate a canonical short or extended command APDU."""

        raw = bytes(encoded)
        if len(raw) < 4:
            raise ValueError("An APDU must contain a four-byte header")
        header = raw[:4]
        tail = raw[4:]
        if not tail:
            return cls(*header)
        if len(tail) == 1:
            return cls(*header, le=f"{tail[0]:02X}")
        if tail[0] != 0:
            lc = tail[0]
            if len(tail) not in (lc + 1, lc + 2):
                raise ValueError("Short APDU Lc/Le is inconsistent with its size")
            data = tail[1 : lc + 1]
            le = tail[-1:] if len(tail) == lc + 2 else b""
            return cls(*header, lc=lc, data=data, le=le)
        if len(tail) == 3:
            return cls(*header, le=tail[1:].hex(), extended=True)
        if len(tail) < 4:
            raise ValueError("Truncated extended APDU")
        lc = int.from_bytes(tail[1:3], "big")
        if lc == 0 or len(tail) not in (lc + 3, lc + 5):
            raise ValueError("Extended APDU Lc/Le is inconsistent with its size")
        data = tail[3 : lc + 3]
        le = tail[-2:] if len(tail) == lc + 5 else b""
        return cls(*header, lc=lc, data=data, le=le, extended=True)

    def with_le(self, le):
        """Clone this command while replacing its expected response length."""

        return APDUCommand(self.cla, self.ins, self.p1, self.p2, self.lc, self.data, le, extended=self.extended)

    def __repr__(self):
        output = (
            f"Command APDU [Class: {self.cla} Instruction: {self.ins} Parameter 1: {self.p1} Parameter 2: {self.p2}]"
        )
        if self.data:
            output += f" [Data: {self.data} (len {self.lc})]"
        if self.le:
            output += f" [Expected Response Length: {self.le}]"
        return output


class APDUResponse:
    Status = {
        0x61: "SW2 indicates the number of response bytes still available",
        0x62: {
            0x00: "No information given",
            0x81: "Part of returned data may be corrupted",
            0x82: "End of file/record reached before reading Le bytes",
            0x83: "Selected file invalidated",
            0x84: "FCI not formatted according to ISO7816-4 section 5.1.5",
        },
        0x63: {
            0x00: "No information given",
            0x81: "File filled up by the last write",
            0x82: "Card Key not supported",
            0x83: "Reader Key not supported",
            0x84: "Plain transmission not supported",
            0x85: "Secured Transmission not supported",
            0x86: "Volatile memory not available",
            0x87: "Non Volatile memory not available",
            0x88: "Key number not valid",
            0x89: "Key length is not correct",
            0x0C: "Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)",
        },
        0x64: "State of non-volatile memory unchanged (SW2=00, other values are RFU)",
        0x65: {0x00: "No information given", 0x81: "Memory failure"},
        0x66: "Reserved for security-related issues (not defined in this part of ISO/IEC 7816)",
        0x67: {0x00: "Wrong length"},
        0x68: {
            0x00: "No information given",
            0x81: "Logical channel not supported",
            0x82: "Secure messaging not supported",
        },
        0x69: {
            0x00: "No information given",
            0x81: "Command incompatible with file structure",
            0x82: "Security status not satisfied",
            0x83: "Authentication method blocked",
            0x84: "Referenced data invalidated",
            0x85: "Conditions of use not satisfied",
            0x86: "Command not allowed (no current EF)",
            0x87: "Expected SM data objects missing",
            0x88: "SM data objects incorrect",
        },
        0x6A: {
            0x00: "No information given",
            0x80: "Incorrect parameters in the data field",
            0x81: "Function not supported",
            0x82: "File not found",
            0x83: "Record not found",
            0x84: "Not enough memory space in the file",
            0x85: "Lc inconsistent with TLV structure",
            0x86: "Incorrect parameters P1-P2",
            0x87: "Lc inconsistent with P1-P2",
            0x88: "Referenced data not found",
        },
        0x6B: {0x00: "Wrong parameter(s) P1-P2"},
        0x6C: "Wrong length Le: SW2 indicates the exact length",
        0x6D: {0x00: "Instruction code not supported or invalid"},
        0x6E: {0x00: "No precise diagnosis"},
        0x90: {0x00: "Success"},
    }

    def __init__(self, data, sw1, sw2, *, authenticated=None):
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
        self.status = self.describe(sw1, sw2)
        # None means that authenticity is not applicable/known (for example a
        # plaintext session).  Secure-Messaging implementations set this to
        # True only after verifying DO'8E', or False for a permitted bare
        # transport/checking error.
        self.authenticated = authenticated

    @classmethod
    def describe(cls, sw1, sw2):
        """Translate a status word into a human-readable string.

        Handles both shapes of the Status table: a dict keyed by sw2, and a
        single string that covers every sw2 for that sw1. Returns
        "Unknown error" when the status word is not listed.
        """
        entry = cls.Status.get(sw1)
        if isinstance(entry, dict):
            return entry.get(sw2, "Unknown error")
        if isinstance(entry, str):
            return entry
        return "Unknown error"

    def raw(self):
        return bytes(list(self.data) + [self.sw1] + [self.sw2])

    def __str__(self):
        return to_hex_string(list(self.data) + [self.sw1, self.sw2])

    def __repr__(self):
        return (
            f"APDU Response [Data: {to_hex_string(self.data)}] "
            f"[Status Word 1: {hex(self.sw1)}] [Status Word 2: {hex(self.sw2)}] ({self.status})"
        )


class ISO7816Exception(Exception):
    def __init__(self, data, sw1=None, sw2=None):
        super().__init__(data, sw1, sw2)
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2


class APDUDroppedException(ISO7816Exception):
    """Raised when the interceptor drops a command APDU before it is sent.

    The card is never contacted and Secure Messaging state (the SSC) is left
    untouched, so subsequent transmits stay in sync with the chip.
    """

    def __init__(self, apdu):
        super().__init__(f"APDU dropped by interceptor: {repr(apdu)}")
        self.apdu = apdu


class SecureMessagingChannel(Protocol):
    def protect(self, command: APDUCommand) -> APDUCommand: ...

    def unprotect(self, response: APDUResponse) -> APDUResponse: ...


class ISO7816:
    def __init__(self, reader):
        self._reader = reader
        self.ciphering: SecureMessagingChannel | None = None
        # Origin label stamped on every APDU this channel records, so the
        # Traffic view can tell read / forge / security traffic apart. A caller
        # may override it per-transmit; otherwise this channel-wide default is
        # used. The owning tab sets it (e.g. "read", "forge", "security").
        self.source = "tool"
        self.logical_channel = 0
        self._channel_applications = {0: None}

    @property
    def reader_connection(self):
        """The current reader connection, including one replaced by a reset."""

        return self._reader

    @property
    def current_application(self):
        return self._channel_applications.get(self.logical_channel)

    @current_application.setter
    def current_application(self, value):
        self._channel_applications[self.logical_channel] = value

    def transmit(
        self,
        toSend,
        logMsg=None,
        full=False,
        source=None,
        *,
        auto_get_response=True,
        auto_correct_le=True,
        max_followups=16,
    ):
        """
        @param toSend: The command to transmit.
        @type toSend: An APDUCommand object.
        @param logMsg: A log message associated to the transmit.
        @type logMsg: A string.
        @param source: Origin label recorded in APDU history. When None
            (the default), the channel's L{source} attribute is used.
        @return: The result field of the responseAPDU object

        The P1 and P2 fields are checked after each transmit.
        If they don't mean success, the appropriate error string is retrieved
        from the Error dictionary and an ISO7816Exception is raised.
        The ISO7816Exception is composed of three fields: ('error message', p1, p2)
        """

        response = self._transmit_once(toSend, logMsg, source)
        command = toSend

        # ISO 7816-4 procedure-byte handling belongs above Secure Messaging:
        # each retry/follow-up is protected separately and therefore advances
        # the send-sequence counter exactly once.
        if response.sw1 == 0x6C and auto_correct_le and not (self.ciphering is not None and response.authenticated is False):
            corrected_le = "0000" if command.extended and response.sw2 == 0 else f"{response.sw2:02X}"
            response = self._transmit_once(command.with_le(corrected_le), "Correct Le after SW=6Cxx", source)

        if response.sw1 == 0x61 and auto_get_response and not (self.ciphering is not None and response.authenticated is False):
            accumulated = bytearray(response.data)
            authenticated = response.authenticated
            followups = 0
            while response.sw1 == 0x61:
                followups += 1
                if followups > max_followups:
                    raise ISO7816Exception("Too many SW=61xx GET RESPONSE follow-ups", response.sw1, response.sw2)
                le = response.sw2 or 0x100
                followup = APDUCommand(command.cla, "C0", "00", "00", le=le)
                response = self._transmit_once(followup, "GET RESPONSE after SW=61xx", source)
                accumulated.extend(response.data)
                if response.authenticated is False:
                    authenticated = False
                elif authenticated is None:
                    authenticated = response.authenticated
            response = APDUResponse(accumulated, response.sw1, response.sw2, authenticated=authenticated)

        if full:
            return response
        # 62xx/63xx are processing-complete warnings and may carry valuable
        # partial bytes (notably 6282 EOF). Preserve the bytes for the caller.
        if response.sw1 in (0x90, 0x62, 0x63):
            return bytes(response.data)
        logging.debug(f"APDU Response Error: {response.status} [{hex(response.sw1)}] [{hex(response.sw2)}]")
        raise ISO7816Exception(response.status, response.sw1, response.sw2)

    def _transmit_once(self, toSend, logMsg=None, source=None):
        """Exchange and record exactly one physical command APDU."""

        # Resolve the origin label: an explicit argument wins, else the
        # channel-wide default set by the owning tab.
        if source is None:
            source = self.source

        # Capture cleartext command before any SM wrapping
        cleartext_cmd = toSend

        log_enc = ""
        if logMsg:
            logging.debug(f"Transmit APDU: {logMsg}")

        # Intercept the cleartext command BEFORE Secure Messaging wrapping, so
        # edits change exactly what the chip authenticates/decrypts. A None
        # result means "drop": short-circuit without touching the card and
        # without advancing the SSC (protect() is never called), keeping the
        # secure channel in sync for later traffic. The history then records the
        # command as the chip actually received it (post-edit).
        intercepted = Interceptor().intercept(cleartext_cmd)
        if intercepted is None:
            logging.debug(f"APDU dropped by interceptor: {repr(cleartext_cmd)}")
            APDUHistory.get().record(
                APDUTransaction(
                    request_cla=cleartext_cmd.cla,
                    request_ins=cleartext_cmd.ins,
                    request_p1=cleartext_cmd.p1,
                    request_p2=cleartext_cmd.p2,
                    request_lc=cleartext_cmd.lc,
                    request_data=cleartext_cmd.data,
                    request_le=cleartext_cmd.le,
                    response_data="",
                    response_sw1=0,
                    response_sw2=0,
                    sm_active=self.ciphering is not None,
                    sm_type="",
                    source=source,
                    comment="Dropped by interceptor",
                )
            )
            raise APDUDroppedException(cleartext_cmd)
        toSend = cleartext_cmd = intercepted

        ciphering = self.ciphering
        sm_active = ciphering is not None
        sm_type = ""
        if ciphering is not None:
            cls_name = type(ciphering).__name__
            sm_type = "AES" if "Aes" in cls_name else "3DES"
            log_enc = "Encrypted "
            toSend = ciphering.protect(toSend)

        logging.debug(f"> {log_enc}{repr(toSend)}")

        # Wire request: the bytes actually transmitted (SM-protected when SM is
        # on, otherwise identical to the cleartext command).
        wire_request_hex = to_hex_string(toSend.raw())

        data, sw1, sw2 = self._reader.transmit(toSend.raw())

        # Wire response: the raw data + SW exactly as received, captured before
        # unprotect so the protected DOs are preserved in the history.
        wire_response = APDUResponse(data, sw1, sw2)
        wire_response_hex = to_hex_string(wire_response.raw())

        response = wire_response
        unprotect_error = None
        if ciphering is not None:
            try:
                response = ciphering.unprotect(response)
            except Exception as exc:
                unprotect_error = exc
                response.authenticated = False

        logging.debug(f"< {log_enc}{repr(response)})")

        APDUHistory.get().record(
            APDUTransaction(
                request_cla=cleartext_cmd.cla,
                request_ins=cleartext_cmd.ins,
                request_p1=cleartext_cmd.p1,
                request_p2=cleartext_cmd.p2,
                request_lc=cleartext_cmd.lc,
                request_data=cleartext_cmd.data,
                request_le=cleartext_cmd.le,
                response_data=to_hex_string(response.data) if response.data else "",
                response_sw1=response.sw1,
                response_sw2=response.sw2,
                sm_active=sm_active,
                sm_type=sm_type,
                source=source,
                wire_request_hex=wire_request_hex,
                wire_response_hex=wire_response_hex,
                response_authenticated=response.authenticated,
                comment=(f"Secure Messaging verification failed: {unprotect_error}" if unprotect_error else ""),
            )
        )
        if unprotect_error is not None:
            raise unprotect_error
        return response

    def transmit_raw(self, raw, source=None):
        """Exchange exact wire bytes with the card and return its raw response.

        Unlike :meth:`transmit`, this method does not parse or modify the
        command, run the interceptor, apply Secure Messaging, decrypt the
        response, or raise for a non-9000 status word.  It is intended for
        protocol research and permits deliberately malformed or already
        protected APDUs.  The exchange is still recorded in
        :class:`~pypassport.apdu_history.APDUHistory` with the exact bytes.

        Sending a Secure-Messaging frame this way does not advance the local
        Secure-Messaging state.  Callers that do so should clear/re-establish
        the local channel before using :meth:`transmit` again.

        @param raw: Bytes, a list of byte values, or a hexadecimal string.
        @param source: APDU-history origin label.
        @return: The unmodified :class:`APDUResponse` from PC/SC.
        """

        if isinstance(raw, str):
            clean = "".join(raw.split()).replace(":", "")
            try:
                request = bytes.fromhex(clean)
            except ValueError as exc:
                raise ISO7816Exception("Raw APDU is not valid hexadecimal") from exc
        else:
            try:
                request = bytes(raw) if isinstance(raw, (bytes, bytearray)) else bytes(to_bytes(raw))
            except (TypeError, ValueError) as exc:
                raise ISO7816Exception("Raw APDU must be bytes, a byte list, or hexadecimal") from exc

        if not request:
            raise ISO7816Exception("Raw APDU must contain at least one byte")
        if source is None:
            source = self.source

        data, sw1, sw2 = self._reader.transmit(list(request))
        response = APDUResponse(data, sw1, sw2)

        # These cleartext-oriented fields are only a best-effort header view;
        # wire_request_hex/wire_response_hex below are authoritative.
        request_hex = request.hex().upper()
        padded_header = request_hex[:8].ljust(8, "0")
        cls_name = type(self.ciphering).__name__ if self.ciphering is not None else ""
        sm_type = "AES" if "Aes" in cls_name else ("3DES" if cls_name else "")
        APDUHistory.get().record(
            APDUTransaction(
                request_cla=padded_header[0:2] if len(request) >= 1 else "",
                request_ins=padded_header[2:4] if len(request) >= 2 else "",
                request_p1=padded_header[4:6] if len(request) >= 3 else "",
                request_p2=padded_header[6:8] if len(request) >= 4 else "",
                request_lc=request_hex[8:10] if len(request) >= 5 else "",
                request_data=request_hex[10:] if len(request) >= 6 else "",
                request_le="",
                response_data=to_hex_string(response.data) if response.data else "",
                response_sw1=response.sw1,
                response_sw2=response.sw2,
                sm_active=self.ciphering is not None,
                sm_type=sm_type,
                source=source,
                wire_request_hex=request_hex,
                wire_response_hex=to_hex_string(response.raw()),
                response_authenticated=None,
            )
        )
        return response

    def rst_connection_raw(self):
        reader_name = self._reader.getReader()
        try:
            self._reader.disconnect()
            self._reader = reader.get_reader(reader_name)
            self._reader.connect()
            self.ciphering = None
            self._channel_applications = {0: None}
            self.logical_channel = 0
            return
        except Exception as e:
            raise ISO7816Exception(f"An error occured while resetting the connection: {e}")

    def rst_connection(self):
        try:
            self.rst_connection_raw()
            self.select_dedicated_file("A0000002471001")
        except Exception as e:
            raise ISO7816Exception(f"An error occured while resetting the connection: {e}")

    def select_file(self, p1, p2, file):
        toSend = APDUCommand(self.channel_cla(), "A4", p1, p2, data=file)
        result = self.transmit(toSend, f"Select File {file}")
        if str(p1).upper() == "04":
            self.current_application = str(file).upper()
        elif str(p1).upper() == "00" and str(file).upper() == "3F00":
            self.current_application = "MF"
        return result

    def select_elementary_file(self, file):
        return self.select_file("02", "0C", file)

    def select_dedicated_file(self, file):
        result = self.select_file("04", "0C", file)
        self.current_application = str(file).upper()
        return result

    def select_master_file(self):
        result = self.select_file("00", "0C", "3F00")
        self.current_application = "MF"
        return result

    def select_context(self, reference):
        """Select the owning application and EF for a FileReference."""
        from pypassport.doc9303.file_context import MF, resolve_file

        ref = resolve_file(reference)
        if self.current_application != ref.application:
            if ref.application == MF:
                self.select_master_file()
            else:
                self.select_dedicated_file(ref.application)
        self.select_elementary_file(ref.fid)
        return ref

    def read_binary(self, offset, nbOfByte):
        offset = int(offset)
        if offset < 0:
            raise ValueError("READ BINARY offset must be non-negative")
        if offset > 0x7FFF:
            return self.read_binary_odd(offset, nbOfByte)
        os = "%04x" % offset
        toSend = APDUCommand(self.channel_cla(), "B0", os[0:2], os[2:4], le=int(nbOfByte))
        return self.transmit(toSend, f"Reading binary at offset {offset} - expecting {nbOfByte} bytes")

    def read_binary_response(self, offset, nbOfByte):
        """READ BINARY variant that preserves authenticated warning status."""
        offset = int(offset)
        if offset > 0x7FFF:
            width = max(1, (offset.bit_length() + 7) // 8)
            command = APDUCommand(self.channel_cla(), "B1", "00", "00", data=bytes([0x54, width]) + offset.to_bytes(width, "big"), le=int(nbOfByte))
        else:
            encoded = f"{offset:04X}"
            command = APDUCommand(self.channel_cla(), "B0", encoded[:2], encoded[2:], le=int(nbOfByte))
        return self.transmit(command, full=True)

    def read_selected_binary_all(self, *, chunk_size=256, maximum=0x100000):
        """Read a selected transparent EF when no trustworthy length wrapper exists."""
        output = bytearray()
        while len(output) < maximum:
            response = self.read_binary_response(len(output), min(chunk_size, maximum - len(output)))
            output.extend(response.data)
            if response.sw1 == 0x62 and response.sw2 == 0x82 or len(response.data) < chunk_size:
                break
            if response.sw1 != 0x90:
                raise ISO7816Exception(response.status, response.sw1, response.sw2)
        if len(output) == maximum:
            raise ISO7816Exception("Transparent EF exceeds the configured safety bound")
        return bytes(output)

    def transmit_chained(self, command, *, chunk_size=224, source=None):
        """Send long cleartext command data with ISO command chaining."""
        payload = bytes.fromhex(command.data)
        if len(payload) <= chunk_size:
            return self.transmit(command, source=source)
        response = b""
        for start in range(0, len(payload), chunk_size):
            final = start + chunk_size >= len(payload)
            cla = int(command.cla, 16) | (0 if final else 0x10)
            part = APDUCommand(cla, command.ins, command.p1, command.p2, data=payload[start:start+chunk_size], le=command.le if final else "")
            response = self.transmit(part, source=source)
        return response

    def read_binary_odd(self, offset, nbOfByte, *, sfi=None):
        """ISO 7816 odd-INS READ BINARY with an offset data object."""
        offset = int(offset)
        width = max(1, (offset.bit_length() + 7) // 8)
        if width > 4:
            raise ValueError("Enhanced READ BINARY offset exceeds four bytes")
        payload = bytes([0x54, width]) + offset.to_bytes(width, "big")
        if sfi is not None:
            payload = bytes([0x51, 1, int(sfi) & 0x1F]) + payload
        command = APDUCommand(self.channel_cla(), "B1", "00", "00", data=payload, le=int(nbOfByte))
        return self.transmit(command, f"Odd READ BINARY at offset {offset} - expecting {nbOfByte} bytes")

    def read_binary_sf(self, shortFileID, offset, nbOfByte):
        os = "%02x" % int(offset)
        sfi = int(str(shortFileID), 16) if isinstance(shortFileID, str) else int(shortFileID)
        p1 = sfi if sfi & 0x80 else 0x80 | (sfi & 0x1F)
        toSend = APDUCommand(self.channel_cla(), "B0", p1, os, le=int(nbOfByte))
        return self.transmit(
            toSend, f"Reading binary with SFID {shortFileID} at offset {offset} - expecting {nbOfByte} bytes"
        )

    def update_binary(self, offset, data):
        os = "%04x" % int(offset)
        toSend = APDUCommand(self.channel_cla(), "D6", os[0:2], os[2:4], data=data)
        return self.transmit(toSend, "Update Binary")

    def get_uid(self):
        toSend = APDUCommand("FF", "CA", "00", "00", le="00")
        return self.transmit(toSend, "Get UID")

    def get_atr(self):
        """Return the reader connection's Answer To Reset bytes."""

        return bytes(self._reader.getATR())

    @staticmethod
    def encode_logical_channel(cla, channel):
        """Apply ISO interindustry logical-channel coding for channels 0..19."""
        cla, channel = int(str(cla), 16) if isinstance(cla, str) else int(cla), int(channel)
        if not 0 <= channel <= 19:
            raise ValueError("Logical channel must be in range 0..19")
        if channel <= 3:
            return (cla & 0xFC) | channel
        return (cla & 0x90) | 0x40 | (channel - 4)

    def channel_cla(self, cla="00"):
        return self.encode_logical_channel(cla, self.logical_channel)

    def open_logical_channel(self, channel=0):
        """Open an available channel (P1=00) or the requested channel."""
        p1 = "00" if channel == 0 else f"{int(channel):02X}"
        response = self.transmit(APDUCommand("00", "70", p1, "00", le=1))
        opened = response[0] if response else int(channel)
        if not 1 <= opened <= 19:
            raise ISO7816Exception("Card returned an invalid logical channel")
        return opened

    def close_logical_channel(self, channel):
        channel = int(channel)
        return self.transmit(APDUCommand(self.encode_logical_channel("00", channel), "70", "80", channel))

    def internal_authentication(self, rnd_ifd):
        toSend = APDUCommand(self.channel_cla(), "88", "00", "00", data=rnd_ifd, le="00")
        return self.transmit(toSend, "Internal Authentication")

    def get_challenge(self):
        toSend = APDUCommand(self.channel_cla(), "84", "00", "00", le="08")
        return self.transmit(toSend, "Get Challenge")

    def mutual_authentication(self, eifd_mifd):
        toSend = APDUCommand(self.channel_cla(), "82", "00", "00", data=eifd_mifd, le="28")
        return self.transmit(toSend, "Mutual Authentication")

    def mse_set_at(self, pace_oid, reference, domain_params=b"", chat=b""):
        self.ciphering = None
        pace_oid = bytes([0x80, len(pace_oid)]) + pace_oid
        reference = bytes([0x83, len(reference)]) + reference
        if chat:
            chat = bytes([0x7F, 0x4C, len(chat)]) + chat
        if domain_params:
            domain_params = bytes([0x84, len(domain_params)]) + domain_params
        payload = pace_oid + reference + chat + domain_params
        toSend = APDUCommand(self.channel_cla(), "22", "C1", "A4", data=payload)
        return self.transmit(toSend, "MSE:Set At")

    def general_authenticate(self):
        toSend = APDUCommand(self.channel_cla("10"), "86", "00", "00", data="7C00", le="00")
        return self.transmit(toSend, "General Authenticate")
