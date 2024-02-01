import logging

from pypassport.apdu import CommandAPDU, ResponseAPDU
from pypassport.iso9797 import pad, unpad, mac
from Crypto.Cipher import DES3, DES
from pypassport import hexfunctions
from pypassport import asn1
from pypassport.logger import Logger


class Ciphering(Logger):
    def __init__(self):
        Logger.__init__(self, "SM")

    def protect(self, apdu):
        raise Exception("Should be implemented")

    def unprotect(self, apdu):
        raise Exception("Should be implemented")


class SecureMessagingException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class SecureMessaging(Ciphering):
    """
    This class implements the secure messaging protocol.
    The class is a new layer that comes between the reader and the iso7816.
    It gives a new transmit method that takes an APDU object formed by the iso7816 layer,
    ciphers it following the doc9303 specification, sends the ciphered APDU to the reader layer and returns the unciphered APDU.
    """

    def __init__(self, ksenc, ksmac, ssc):
        Ciphering.__init__(self)
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

        tmp = "Concatenate CmdHeader"
        if (apdu.getData()):
            tmp += " and DO87"
            do87 = self._buildD087(apdu)
        if (apdu.getLe()):
            tmp += " and DO97"
            do97 = self._buildD097(apdu)

        M = cmdHeader + do87 + do97
        logging.debug(tmp)
        logging.debug("\tM: " + hexfunctions.binToHexRep(M))

        self._ssc = self._incSSC()
        logging.debug("Compute MAC of M")
        logging.debug("\tIncrement SSC with 1")
        logging.debug("\t\tSSC: " + hexfunctions.binToHexRep(self._ssc))

        N = pad(self._ssc + M)
        logging.debug("\tConcateate SSC and M and add padding")
        logging.debug("\t\tN: " + hexfunctions.binToHexRep(N))

        CC = mac(self._ksmac, N)
        logging.debug("\tCompute MAC over N with KSmac")
        logging.debug("\t\tCC: " + hexfunctions.binToHexRep(CC))

        do8e = self._buildD08E(CC)
        size = str(len(do87) + len(do97) + len(do8e))
        protectedAPDU = cmdHeader[:4] + hexfunctions.intToBin(size) + do87 + do97 + do8e + hexfunctions.hexToBin(0x00)

        logging.debug("Construct and send protected APDU")

        return CommandAPDU(
            hexfunctions.binToHexRep(protectedAPDU[0]),
            hexfunctions.binToHexRep(protectedAPDU[1]),
            hexfunctions.binToHexRep(protectedAPDU[2]),
            hexfunctions.binToHexRep(protectedAPDU[3]),
            hexfunctions.binToHexRep(protectedAPDU[4]),
            hexfunctions.binToHexRep(protectedAPDU[5:-1]),
            hexfunctions.binToHexRep(protectedAPDU[-1])
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

        rapdu = rapdu.getBinAPDU()

        # DO'87'
        # Mandatory if data is returned, otherwise absent
        if rapdu[0] == 0x87:
            (encDataLength, o) = asn1.asn1Length(rapdu[1:])
            offset = 1 + o

            if rapdu[offset] != 0x01:
                raise SecureMessagingException("DO87 malformed, must be 87 L 01 <encdata> : " + hexfunctions.binToHexRep(rapdu))

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

        if do99[0:2] != hexfunctions.hexRepToBin("9902"):
            # SM error, return the error code
            return ResponseAPDU([], sw1, sw2)

        # DO'8E'
        # Mandatory id DO'87' and/or DO'99' is present
        if rapdu[offset] == 0x8e:
            ccLength = hexfunctions.binToHex(rapdu[offset + 1])
            CC = rapdu[offset + 2:offset + 2 + ccLength]
            do8e = rapdu[offset:offset + 2 + ccLength]

            # CheckCC

            tmp = ""
            if do87:
                tmp += " DO'87"
            if do99:
                tmp += " DO'99"
            logging.debug("Verify RAPDU CC by computing MAC of" + tmp)

            self._ssc = self._incSSC()
            logging.debug("\tIncrement SSC with 1")
            logging.debug("\t\tSSC: " + hexfunctions.binToHexRep(self._ssc))

            K = pad(self._ssc + do87 + do99)
            logging.debug("\tConcatenate SSC and" + tmp + " and add padding")
            logging.debug("\t\tK: " + hexfunctions.binToHexRep(K))

            logging.debug("\tCompute MAC with KSmac")
            CCb = mac(self._ksmac, K)
            logging.debug("\t\tCC: " + hexfunctions.binToHexRep(CCb))

            res = (CC == CCb)
            logging.debug("\tCompare CC with data of DO'8E of RAPDU")
            logging.debug("\t\t" + hexfunctions.binToHexRep(CC) + " == " + hexfunctions.binToHexRep(CCb) + " ? " + str(res))

            if not res:
                raise SecureMessagingException("Invalid checksum for the rapdu : " + str(hexfunctions.binToHex(rapdu)))

        elif needCC:
            raise SecureMessagingException("Mandatory id DO'87' and/or DO'99' is present")

        data = b''
        if (do87Data):
            # There is a payload
            tdes = DES3.new(self._ksenc, DES.MODE_CBC, b'\x00\x00\x00\x00\x00\x00\x00\x00')
            data = unpad(tdes.decrypt(do87Data))
            logging.debug("Decrypt data of DO'87 with KSenc")

        return ResponseAPDU(data, hexfunctions.binToHex(sw1), hexfunctions.binToHex(sw2))


    def _maskClassAndPad(self, apdu):
        logging.debug("Mask class byte and pad command header")
        res = pad(hexfunctions.hexRepToBin("0C" + apdu.getIns() + apdu.getP1() + apdu.getP2()))
        logging.debug("\tCmdHeader: " + hexfunctions.binToHexRep(res))
        return res


    def _buildD087(self, apdu):
        cipher = b'\x01' + self._padAndEncryptData(apdu)
        res = b'\x87' + asn1.toAsn1Length(len(cipher)) + cipher
        logging.debug("Build DO'87")
        logging.debug("\tDO87: " + hexfunctions.binToHexRep(res))
        return res


    def _padAndEncryptData(self, apdu):
        """ Pad the data, encrypt data with KSenc and build DO'87"""
        tdes = DES3.new(self._ksenc, DES.MODE_CBC, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        paddedData = pad(hexfunctions.hexRepToBin(apdu.getData()))
        enc = tdes.encrypt(paddedData)
        logging.debug("Pad data")
        logging.debug("\tData: " + hexfunctions.binToHexRep(paddedData))
        logging.debug("Encrypt data with KSenc")
        logging.debug("\tEncryptedData: " + hexfunctions.binToHexRep(enc))
        return enc


    def _incSSC(self):
        out = hexfunctions.binToHex(self._ssc) + 1
        res = hexfunctions.hexToBin(out)
        return res


    def _buildD08E(self, mac):
        res = hexfunctions.hexListToBin([0x8E, len(mac)]) + mac
        logging.debug("Build DO'8E")
        logging.debug("\tDO8E: " + hexfunctions.binToHexRep(res))
        return res


    def _buildD097(self, apdu):
        tmp = b"9701" + apdu.getLe().encode("utf-8")
        logging.debug("Build DO'97")
        logging.debug("\tDO97: {}".format(tmp))
        return hexfunctions.hexRepToBin(tmp)


    def __str__(self):
        return "KSenc: " + hexfunctions.binToHexRep(self._ksenc) + "\n" + "KSmac: " + hexfunctions.binToHexRep(self._ksmac) + "\n" + "SSC: " + hexfunctions.binToHexRep(self._ssc)