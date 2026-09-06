import hmac
import logging
from pypassport.iso7816 import APDUCommand, APDUResponse
from pypassport.iso9797 import pad, mac
from Crypto.Cipher import DES3
from pypassport.utils import to_hex_string, to_bytes
from pypassport.asn1 import asn1_length, to_asn1_length


_DEBUG_CRYPTO = False


class SecureMessagingException(Exception):
    pass


class SecureMessaging:
    """
    This class implements the secure messaging protocol.
    The class is a new layer that comes between the reader and the iso7816.
    It gives a new transmit method that takes an APDU object formed by the iso7816 layer,
    ciphers it following the doc9303 specification, sends the ciphered APDU to the reader layer and returns the unciphered APDU.
    """

    def __init__(self, ksenc, ksmac, ssc, *, strict=True):
        self._ksenc = bytes(ksenc)
        self._ksmac = bytes(ksmac)
        self._ssc = bytes(ssc)
        self.strict = strict
        if len(self._ksenc) != 16 or len(self._ksmac) != 16:
            raise SecureMessagingException("BAC/3DES Secure Messaging keys must be 16 bytes")
        if len(self._ssc) != 8:
            raise SecureMessagingException("BAC/3DES Secure Messaging SSC must be 8 bytes")

    @property
    def ssc(self):
        return self._ssc

    @ssc.setter
    def ssc(self, value):
        self._ssc = bytes(value)

    def protect(self, apdu):
        """
        Protect the apdu following the doc9303 specification
        """

        cmdHeader = self._mask_class_and_pad(apdu)
        do87 = b""
        do97 = b""

        debug_msg = "Concatenate CmdHeader"
        if apdu.data:
            debug_msg += " and DO87"
            do87 = self._build_d087(apdu)
        if apdu.le:
            debug_msg += " and DO97"
            do97 = self._build_d097(apdu)

        M = cmdHeader + do87 + do97
        if _DEBUG_CRYPTO:
            logging.debug(debug_msg)
            logging.debug("\tM: " + to_hex_string(M))

        self._ssc = self._inc_ssc()
        if _DEBUG_CRYPTO:
            logging.debug("Compute MAC of M")
            logging.debug("\tIncrement SSC with 1")
            logging.debug("\t\tSSC: " + to_hex_string(self._ssc))

        N = pad(self._ssc + M)
        if _DEBUG_CRYPTO:
            logging.debug("\tConcateate SSC and M and add padding")
            logging.debug("\t\tN: " + to_hex_string(N))

        CC = mac(self._ksmac, N)
        if _DEBUG_CRYPTO:
            logging.debug("\tCompute MAC over N with KSmac")
            logging.debug("\t\tCC: " + to_hex_string(CC))

        do8e = self._build_d08e(CC)
        body = do87 + do97 + do8e

        if _DEBUG_CRYPTO:
            logging.debug("Construct and send protected APDU")

        return APDUCommand(cmdHeader[0], cmdHeader[1], cmdHeader[2], cmdHeader[3], data=body, le="00", extended=len(body) > 0xFF)

    def unprotect(self, rapdu):
        """
        Unprotect the APDU following the iso7816 specification
        """
        needCC = False
        do87 = b""
        do87Data = None
        do99 = b""
        offset = 0

        # A response carrying no Secure Messaging data objects is a bare
        # transport error (the chip rejected the command before SM processing):
        # there is nothing to verify and no response-side SSC step to take, so
        # return it unchanged. A response that *does* carry DO'87'/DO'99'/DO'8E'
        # must be processed even when the outer status word is an error,
        # otherwise the response-side SSC increment is skipped and the channel
        # desynchronises for every subsequent command.
        raw_response = rapdu
        rapdu = bytes(rapdu.data)
        if not rapdu or rapdu[0] not in (0x87, 0x99, 0x8E):
            if raw_response.sw1 in (0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F):
                return APDUResponse([], raw_response.sw1, raw_response.sw2, authenticated=False)
            if self.strict:
                raise SecureMessagingException(
                    "Secure-Messaging response is not protected with DO99/DO8E: "
                    + to_hex_string(raw_response.raw())
                )
            raw_response.authenticated = False
            return raw_response
        # DO'87'
        # Mandatory if data is returned, otherwise absent
        if rapdu[0] == 0x87:
            (encDataLength, o) = asn1_length(rapdu[1:])
            offset = 1 + o

            if offset >= len(rapdu) or rapdu[offset] != 0x01:
                raise SecureMessagingException("DO87 malformed, must be 87 L 01 <encdata> : " + to_hex_string(rapdu))

            do87 = rapdu[0 : offset + encDataLength]
            do87Data = rapdu[offset + 1 : offset + encDataLength]
            offset += encDataLength
            needCC = True

        # DO'99'
        # Mandatory, only absent if SM error occurs
        do99 = rapdu[offset : offset + 4]
        if len(do99) != 4 or do99[0] != 0x99 or do99[1] != 0x02:
            raise SecureMessagingException("DO99 malformed in response: " + to_hex_string(rapdu))
        sw1 = do99[2]
        sw2 = do99[3]
        offset += 4
        if ((raw_response.sw1, raw_response.sw2) != (0x90, 0x00)
                and (raw_response.sw1, raw_response.sw2) != (sw1, sw2)):
            raise SecureMessagingException("Outer and authenticated inner status words conflict")
        needCC = True

        # DO'8E'
        # Mandatory id DO'87' and/or DO'99' is present
        if offset + 2 <= len(rapdu) and rapdu[offset] == 0x8E:
            ccLength = rapdu[offset + 1]
            if ccLength != 8 or offset + 2 + ccLength != len(rapdu):
                raise SecureMessagingException("DO8E has an invalid length or trailing data: " + to_hex_string(rapdu))
            CC = rapdu[offset + 2 : offset + 2 + ccLength]

            # CheckCC
            debug_msg = ""
            if do87:
                debug_msg += " DO'87"
            if do99:
                debug_msg += " DO'99"
            if _DEBUG_CRYPTO:
                logging.debug("Verify RAPDU CC by computing MAC of" + debug_msg)

            self._ssc = self._inc_ssc()
            if _DEBUG_CRYPTO:
                logging.debug("\tIncrement SSC with 1")
                logging.debug("\t\tSSC: " + to_hex_string(self._ssc))

            K = pad(self._ssc + do87 + do99)
            if _DEBUG_CRYPTO:
                logging.debug("\tConcatenate SSC and" + debug_msg + " and add padding")
                logging.debug("\t\tK: " + to_hex_string(K))

            if _DEBUG_CRYPTO:
                logging.debug("\tCompute MAC with KSmac")
            CCb = mac(self._ksmac, K)
            if _DEBUG_CRYPTO:
                logging.debug("\t\tCC: " + to_hex_string(CCb))

            res = hmac.compare_digest(bytes(CC), bytes(CCb))
            if _DEBUG_CRYPTO:
                logging.debug("\tCompare CC with data of DO'8E of RAPDU")
                logging.debug("\t\t" + to_hex_string(CC) + " == " + to_hex_string(CCb) + " ? " + str(res))

            if not res:
                raise SecureMessagingException("Invalid checksum for the rapdu : " + to_hex_string(rapdu))

        elif needCC:
            raise SecureMessagingException("Mandatory id DO'87' and/or DO'99' is present")

        data = b""
        if do87Data:
            # There is a payload
            if len(do87Data) % 8:
                raise SecureMessagingException("DO87 ciphertext is not a 3DES block sequence")
            tdes = DES3.new(self._ksenc, DES3.MODE_CBC, b"\x00\x00\x00\x00\x00\x00\x00\x00")
            plaintext = tdes.decrypt(do87Data)
            data = _unpad(plaintext, strict=self.strict)
            if _DEBUG_CRYPTO:
                logging.debug("Decrypt data of DO'87 with KSenc")

        return APDUResponse(data, sw1, sw2, authenticated=True)

    def _mask_class_and_pad(self, apdu):
        if _DEBUG_CRYPTO:
            logging.debug("Mask class byte and pad command header")
        clear_cla = int(apdu.cla, 16)
        protected_cla = clear_cla | (0x20 if clear_cla & 0x40 else 0x0C)
        res = pad(bytes([protected_cla]) + to_bytes(apdu.ins + apdu.p1 + apdu.p2))
        if _DEBUG_CRYPTO:
            logging.debug("\tCmdHeader: " + to_hex_string(res))
        return res

    def _build_d087(self, apdu):
        cipher = b"\x01" + self._pad_and_encrypt_data(apdu)
        res = b"\x87" + to_asn1_length(len(cipher)) + cipher
        if _DEBUG_CRYPTO:
            logging.debug("Build DO'87")
            logging.debug("\tDO87: " + to_hex_string(res))
        return res

    def _pad_and_encrypt_data(self, apdu):
        """Pad the data, encrypt data with KSenc and build DO'87"""
        tdes = DES3.new(self._ksenc, DES3.MODE_CBC, b"\x00\x00\x00\x00\x00\x00\x00\x00")
        paddedData = pad(to_bytes(apdu.data))
        enc = tdes.encrypt(paddedData)
        if _DEBUG_CRYPTO:
            logging.debug("Pad data")
            logging.debug("\tData: " + to_hex_string(paddedData))
            logging.debug("Encrypt data with KSenc")
            logging.debug("\tEncryptedData: " + to_hex_string(enc))
        return enc

    def _inc_ssc(self):
        out = int.from_bytes(self._ssc, byteorder="big") + 1
        return out.to_bytes(8, byteorder="big")

    def _build_d08e(self, mac):
        res = bytes([0x8E, len(mac)]) + mac
        if _DEBUG_CRYPTO:
            logging.debug("Build DO'8E")
            logging.debug("\tDO8E: " + to_hex_string(res))
        return res

    def _build_d097(self, apdu):
        if _DEBUG_CRYPTO:
            logging.debug("Build DO'97")
            logging.debug(f"\tDO97: {apdu.le}")
        le = to_bytes(apdu.le)
        return bytes([0x97, len(le)]) + le

    def __str__(self):
        return "KSenc: [REDACTED]\nKSmac: [REDACTED]\nSSC: " + to_hex_string(self._ssc)


def _unpad(data: bytes, *, strict: bool) -> bytes:
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    if i >= 0 and data[i] == 0x80:
        return data[:i]
    if strict:
        raise SecureMessagingException("Invalid ISO/IEC 7816 padding")
    return data
