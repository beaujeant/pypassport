"""
AES-based Secure Messaging for PACE (ICAO Doc 9303 Part 11 / BSI TR-03110).

After a successful PACE run, the chip negotiates an AES session instead of
the 3DES session used by BAC.  The protocol differences from SecureMessaging:

* Block size / padding target: 16 bytes (AES) vs 8 bytes (3DES).
* Encryption IV:  AES-ECB(K_enc, SSC) — a fresh IV per APDU rather than a
  fixed zero IV.
* MAC algorithm:  AES-CMAC (16-byte output, truncated to 8 bytes for DO'8E).
* SSC width:      16 bytes (one AES block) rather than 8.

The protect/unprotect interface is identical to SecureMessaging so that
``ISO7816.ciphering`` can hold either object transparently.
"""

import hmac
import logging

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from pypassport.asn1 import asn1_length, to_asn1_length
from pypassport.iso7816 import APDUCommand, APDUResponse
from pypassport.utils import to_bytes, to_hex_string


_DEBUG_CRYPTO = False

# Length of the MAC tag placed in DO'8E (first 8 bytes of the 16-byte CMAC).
_MAC_LEN = 8
_BLOCK = AES.block_size  # 16


class AesSecureMessagingException(Exception):
    pass


class AesSecureMessaging:
    """
    Secure Messaging using AES-CBC encryption and AES-CMAC authentication,
    as specified in BSI TR-03110 Part 2 §9.8 and ICAO Doc 9303 Part 11.

    :param ksenc: Session encryption key (16, 24, or 32 bytes).
    :param ksmac: Session MAC key (same length as ksenc).
    :param ssc:   Initial Send Sequence Counter (16 zero bytes).
    """

    def __init__(self, ksenc: bytes, ksmac: bytes, ssc: bytes, *, strict: bool = True):
        self._ksenc = bytes(ksenc)
        self._ksmac = bytes(ksmac)
        self._ssc = bytes(ssc)
        self.strict = strict
        if len(self._ksenc) not in (16, 24, 32) or len(self._ksmac) != len(self._ksenc):
            raise AesSecureMessagingException("AES Secure Messaging keys must have equal 16/24/32-byte lengths")
        if len(self._ssc) != 16:
            raise AesSecureMessagingException("AES Secure Messaging SSC must be 16 bytes")

    @property
    def ssc(self) -> bytes:
        return self._ssc

    @ssc.setter
    def ssc(self, value: bytes) -> None:
        self._ssc = bytes(value)

    # ------------------------------------------------------------------
    # Public interface (mirrors SecureMessaging)
    # ------------------------------------------------------------------

    def protect(self, apdu: APDUCommand) -> APDUCommand:
        """Encrypt and MAC-protect a command APDU."""
        self._ssc = self._inc_ssc()

        cmd_header = self._mask_class_and_pad(apdu)

        do87 = b""
        do97 = b""
        if apdu.data:
            do87 = self._build_do87(apdu)
        if apdu.le:
            do97 = self._build_do97(apdu)

        M = cmd_header + do87 + do97
        if _DEBUG_CRYPTO:
            logging.debug("SM protect M: %s", to_hex_string(M))

        N = _iso_pad(self._ssc + M)
        CC = self._cmac(N)[:_MAC_LEN]
        if _DEBUG_CRYPTO:
            logging.debug("SM protect CC: %s", to_hex_string(CC))

        do8e = bytes([0x8E, _MAC_LEN]) + CC
        body = do87 + do97 + do8e
        return APDUCommand(cmd_header[0], cmd_header[1], cmd_header[2], cmd_header[3], data=body, le="00", extended=len(body) > 0xFF)

    def unprotect(self, rapdu: APDUResponse) -> APDUResponse:
        """Verify MAC and decrypt a response APDU."""
        # A response carrying no Secure Messaging data objects is a bare
        # transport error (the chip rejected the command before SM processing):
        # there is nothing to verify and no response-side SSC step to take, so
        # return it unchanged. A response that *does* carry DO'87'/DO'99'/DO'8E'
        # must be processed even when the outer status word is an error,
        # otherwise the response-side SSC increment is skipped and the channel
        # desynchronises for every subsequent command.
        raw = bytes(rapdu.data)
        if not raw or raw[0] not in (0x87, 0x99, 0x8E):
            # ISO 7816 checking errors can be returned before the chip accepts
            # the command as an SM message.  They are explicitly
            # unauthenticated and therefore may never carry success/data.
            if rapdu.sw1 in (0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F):
                return APDUResponse([], rapdu.sw1, rapdu.sw2, authenticated=False)
            if self.strict:
                raise AesSecureMessagingException(
                    "Secure-Messaging response is not protected with DO99/DO8E: " + to_hex_string(rapdu.raw())
                )
            rapdu.authenticated = False
            return rapdu
        offset = 0

        do87 = b""
        do87_data = None

        # DO'87' — present only when the response carries encrypted data.
        if raw[offset] == 0x87:
            enc_len, o = asn1_length(raw[offset + 1 :])
            inner_start = offset + 1 + o
            if inner_start >= len(raw) or raw[inner_start] != 0x01:
                raise AesSecureMessagingException("DO87 malformed (missing 0x01 indicator): " + to_hex_string(raw))
            do87 = raw[offset : inner_start + enc_len]
            do87_data = raw[inner_start + 1 : inner_start + enc_len]
            offset = inner_start + enc_len

        # DO'99' — always present (status word echo).
        do99 = raw[offset : offset + 4]
        if len(do99) < 4 or do99[0] != 0x99 or do99[1] != 0x02:
            raise AesSecureMessagingException("DO99 malformed in response: " + to_hex_string(raw))
        sw1 = do99[2]
        sw2 = do99[3]
        offset += 4
        if (rapdu.sw1, rapdu.sw2) != (0x90, 0x00) and (rapdu.sw1, rapdu.sw2) != (sw1, sw2):
            raise AesSecureMessagingException("Outer and authenticated inner status words conflict")

        # DO'8E' — MAC.
        if offset + 2 > len(raw) or raw[offset] != 0x8E:
            raise AesSecureMessagingException("DO8E missing in response: " + to_hex_string(raw))
        cc_len = raw[offset + 1]
        if cc_len != _MAC_LEN or offset + 2 + cc_len != len(raw):
            raise AesSecureMessagingException("DO8E has an invalid length or trailing data: " + to_hex_string(raw))
        CC_received = raw[offset + 2 : offset + 2 + cc_len]

        self._ssc = self._inc_ssc()
        K = _iso_pad(self._ssc + do87 + do99)
        CC_computed = self._cmac(K)[:_MAC_LEN]

        if _DEBUG_CRYPTO:
            logging.debug("SM unprotect CC received:  %s", to_hex_string(CC_received))
            logging.debug("SM unprotect CC computed:  %s", to_hex_string(CC_computed))

        if not hmac.compare_digest(bytes(CC_received), bytes(CC_computed)):
            raise AesSecureMessagingException("MAC mismatch in response APDU: " + to_hex_string(raw))

        data = b""
        if do87_data is not None:
            if not do87_data or len(do87_data) % _BLOCK:
                raise AesSecureMessagingException("DO87 ciphertext is not a non-empty AES block sequence")
            data = _iso_unpad(self._decrypt(bytes(do87_data)), strict=self.strict)

        return APDUResponse(data, sw1, sw2, authenticated=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _inc_ssc(self) -> bytes:
        val = int.from_bytes(self._ssc, "big") + 1
        return val.to_bytes(16, "big")

    def _encrypt(self, data: bytes) -> bytes:
        """AES-CBC encrypt with IV = AES-ECB(K_enc, SSC)."""
        iv = AES.new(self._ksenc, AES.MODE_ECB).encrypt(self._ssc)
        return AES.new(self._ksenc, AES.MODE_CBC, iv).encrypt(data)

    def _decrypt(self, data: bytes) -> bytes:
        """AES-CBC decrypt with IV = AES-ECB(K_enc, SSC)."""
        iv = AES.new(self._ksenc, AES.MODE_ECB).encrypt(self._ssc)
        return AES.new(self._ksenc, AES.MODE_CBC, iv).decrypt(data)

    def _cmac(self, data: bytes) -> bytes:
        c = CMAC.new(self._ksmac, ciphermod=AES)
        c.update(data)
        return c.digest()

    def _mask_class_and_pad(self, apdu: APDUCommand) -> bytes:
        """Set CLA to 0x0C and ISO-pad the 4-byte header to 16 bytes."""
        clear_cla = int(apdu.cla, 16)
        protected_cla = clear_cla | (0x20 if clear_cla & 0x40 else 0x0C)
        header = bytes([protected_cla]) + to_bytes(apdu.ins + apdu.p1 + apdu.p2)
        return _iso_pad(header)

    def _build_do87(self, apdu: APDUCommand) -> bytes:
        plain = to_bytes(apdu.data)
        cipher = b"\x01" + self._encrypt(_iso_pad(plain))
        return b"\x87" + to_asn1_length(len(cipher)) + cipher

    def _build_do97(self, apdu: APDUCommand) -> bytes:
        le = to_bytes(apdu.le)
        return bytes([0x97, len(le)]) + le

    def __str__(self):
        return "KSenc: [REDACTED]\nKSmac: [REDACTED]\nSSC: " + to_hex_string(self._ssc)


# ---------------------------------------------------------------------------
# Module-level padding helpers (shared with pace.py)
# ---------------------------------------------------------------------------


def _iso_pad(data: bytes, block_size: int = _BLOCK) -> bytes:
    """ISO/IEC 7816 padding to the given block size (0x80 then 0x00*)."""
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def _iso_unpad(data: bytes, *, strict: bool = False) -> bytes:
    """Remove ISO/IEC 7816 padding."""
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i >= 0 and data[i] == 0x80:
        return data[:i]
    if strict:
        raise AesSecureMessagingException("Invalid ISO/IEC 7816 padding")
    return data
