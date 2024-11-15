import logging
from pypassport.iso7816 import APDUCommand, APDUResponse
from pypassport.iso9797 import pad, unpad, mac
from Crypto.Cipher import DES3, DES
from pypassport.utils import toHexString, toBytes
from pypassport.asn1 import asn1Length, toAsn1Length


DEBUG_CRYPTO = False

class SecureMessagingException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class SecureMessaging():
    """
    This class implements the secure messaging protocol.
    The class is a new layer that comes between the reader and the iso7816.
    It gives a new transmit method that takes an APDU object formed by the iso7816 layer,
    ciphers it following the doc9303 specification, sends the ciphered APDU to the reader layer and returns the unciphered APDU.
    """

    def __init__(self, ksenc, ksmac, ssc):
        self._ksenc = ksenc
        self._ksmac = ksmac
        self._ssc = ssc


    def protect(self, apdu):
        """
        Protect the apdu following the doc9303 specification
        """

        cmdHeader = self._maskClassAndPad(apdu)
        do87 = b""
        do97 = b""

        debug_msg = "Concatenate CmdHeader"
        if apdu.data:
            debug_msg += " and DO87"
            do87 = self._buildD087(apdu)
        if apdu.le:
            debug_msg += " and DO97"
            do97 = self._buildD097(apdu)

        M = cmdHeader + do87 + do97
        if DEBUG_CRYPTO: 
            logging.debug(debug_msg)
            logging.debug("\tM: " + toHexString(M))

        self._ssc = self._incSSC()
        if DEBUG_CRYPTO: 
            logging.debug("Compute MAC of M")
            logging.debug("\tIncrement SSC with 1")
            logging.debug("\t\tSSC: " + toHexString(self._ssc))

        N = pad(self._ssc + M)
        if DEBUG_CRYPTO: 
            logging.debug("\tConcateate SSC and M and add padding")
            logging.debug("\t\tN: " + toHexString(N))

        CC = mac(self._ksmac, N)
        if DEBUG_CRYPTO: 
            logging.debug("\tCompute MAC over N with KSmac")
            logging.debug("\t\tCC: " + toHexString(CC))

        do8e = self._buildD08E(CC)
        size = len(do87) + len(do97) + len(do8e)
        protectedAPDU = cmdHeader[:4] + bytes([size]) + do87 + do97 + do8e + bytes([0x00])

        if DEBUG_CRYPTO: logging.debug("Construct and send protected APDU")

        return APDUCommand(
            protectedAPDU[0],
            protectedAPDU[1],
            protectedAPDU[2],
            protectedAPDU[3],
            protectedAPDU[4],
            protectedAPDU[5:-1],
            protectedAPDU[-1]
        )


    def unprotect(self, rapdu):
        """
        Unprotect the APDU following the iso7816 specification
        """
        needCC = False
        do87 = b""
        do87Data = None
        do99 = b""
        do8e = b""
        offset = 0

        # Check for a SM error
        if (rapdu.sw1 != 0x90 or rapdu.sw2 != 0x00):
            return rapdu

        rapdu = rapdu.raw()

        # DO'87'
        # Mandatory if data is returned, otherwise absent
        if rapdu[0] == 0x87:
            (encDataLength, o) = asn1Length(rapdu[1:])
            offset = 1 + o

            if rapdu[offset] != 0x01:
                raise SecureMessagingException("DO87 malformed, must be 87 L 01 <encdata> : " + toHexString(rapdu))

            do87 = rapdu[0:offset + encDataLength]
            do87Data = rapdu[offset + 1:offset + encDataLength]
            offset += encDataLength
            needCC = True

        # DO'99'
        # Mandatory, only absent if SM error occurs
        do99 = rapdu[offset:offset + 4]
        sw1 = rapdu[offset + 2]
        sw2 = rapdu[offset + 3]
        offset += 4
        needCC = True

        if do99[0] != 0x99 or do99[1] != 0x02:
            # SM error, return the error code
            if DEBUG_CRYPTO: logging.debug("DO99 malformed, must be 9902 instead" + toHexString(rapdu))
            return APDUCommand([], sw1, sw2)

        # DO'8E'
        # Mandatory id DO'87' and/or DO'99' is present
        if rapdu[offset] == 0x8e:
            ccLength = rapdu[offset + 1]
            CC = rapdu[offset + 2:offset + 2 + ccLength]
            do8e = rapdu[offset:offset + 2 + ccLength]

            # CheckCC
            debug_msg = ""
            if do87:
                debug_msg += " DO'87"
            if do99:
                debug_msg += " DO'99"
            if DEBUG_CRYPTO: logging.debug("Verify RAPDU CC by computing MAC of" + debug_msg)

            self._ssc = self._incSSC()
            if DEBUG_CRYPTO: 
                logging.debug("\tIncrement SSC with 1")
                logging.debug("\t\tSSC: " + toHexString(self._ssc))

            K = pad(self._ssc + do87 + do99)
            if DEBUG_CRYPTO: 
                logging.debug("\tConcatenate SSC and" + debug_msg + " and add padding")
                logging.debug("\t\tK: " + toHexString(K))

            if DEBUG_CRYPTO: logging.debug("\tCompute MAC with KSmac")
            CCb = mac(self._ksmac, K)
            if DEBUG_CRYPTO: logging.debug("\t\tCC: " + toHexString(CCb))

            res = (CC == CCb)
            if DEBUG_CRYPTO: 
                logging.debug("\tCompare CC with data of DO'8E of RAPDU")
                logging.debug("\t\t" + toHexString(CC) + " == " + toHexString(CCb) + " ? " + str(res))

            if not res:
                raise SecureMessagingException("Invalid checksum for the rapdu : " + toHexString(rapdu))

        elif needCC:
            raise SecureMessagingException("Mandatory id DO'87' and/or DO'99' is present")

        data = b''
        if (do87Data):
            # There is a payload
            tdes = DES3.new(self._ksenc, DES.MODE_CBC, b'\x00\x00\x00\x00\x00\x00\x00\x00')
            data = unpad(tdes.decrypt(do87Data))
            if DEBUG_CRYPTO: logging.debug("Decrypt data of DO'87 with KSenc")

        return APDUResponse(data, sw1, sw2)


    def _maskClassAndPad(self, apdu):
        if DEBUG_CRYPTO: logging.debug("Mask class byte and pad command header")
        res = pad(toBytes("0C" + apdu.ins + apdu.p1 + apdu.p2))
        if DEBUG_CRYPTO: logging.debug("\tCmdHeader: " + toHexString(res))
        return res


    def _buildD087(self, apdu):
        cipher = b'\x01' + self._padAndEncryptData(apdu)
        res = b'\x87' + toAsn1Length(len(cipher)) + cipher
        if DEBUG_CRYPTO: 
            logging.debug("Build DO'87")
            logging.debug("\tDO87: " + toHexString(res))
        return res


    def _padAndEncryptData(self, apdu):
        """ Pad the data, encrypt data with KSenc and build DO'87"""
        tdes = DES3.new(self._ksenc, DES.MODE_CBC, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        paddedData = pad(toBytes(apdu.data))
        enc = tdes.encrypt(paddedData)
        if DEBUG_CRYPTO:
            logging.debug("Pad data")
            logging.debug("\tData: " + toHexString(paddedData))
            logging.debug("Encrypt data with KSenc")
            logging.debug("\tEncryptedData: " + toHexString(enc))
        return enc


    def _incSSC(self):
        out = int.from_bytes(self._ssc) + 1
        return out.to_bytes(length=8)


    def _buildD08E(self, mac):
        res = bytes([0x8E, len(mac)]) + mac
        if DEBUG_CRYPTO: 
            logging.debug("Build DO'8E")
            logging.debug("\tDO8E: " + toHexString(res))
        return res


    def _buildD097(self, apdu):
        if DEBUG_CRYPTO: 
            logging.debug("Build DO'97")
            logging.debug(f"\tDO97: {apdu.le}")
        return toBytes("9701" + apdu.le)


    def __str__(self):
        return "KSenc: " + toHexString(self._ksenc) + "\n" + "KSmac: " + toHexString(self._ksmac) + "\n" + "SSC: " + toHexString(self._ssc)