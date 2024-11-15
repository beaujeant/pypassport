import logging
from hashlib import sha1
from Crypto import Random
from Crypto.Cipher import DES3
from pypassport.doc9303.mrz import MRZ
from pypassport.utils import toHexString, toBytes
from pypassport.iso9797 import mac, pad
from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport.utils import toHexString

DEBUG_CRYPTO = False

class BACException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class BAC():

    """
    This class performs the Basic Acces Control.
    The main method is I{authenticationAndEstablishmentOfSessionKeys}, it will execute the whole protocol and return the set of keys.
    """

    KENC = b'\x00\x00\x00\x01'
    KMAC = b'\x00\x00\x00\x02'

    def __init__(self, iso7816):
        """
        @param iso7816: A valid iso7816 object connected to a reader.
        @type iso7816: A iso7816 object
        """
        self._iso7816 = iso7816
        self._ksenc = None
        self._ksmac = None
        self._kifd = None
        self._rnd_icc = None
        self._rnd_ifd = None

    def authenticationAndEstablishmentOfSessionKeys(self, mrz):
        """
        Execute the complete BAC process:
            - Derivation of the document basic access keys
            - Mutual authentication
            - Derivation of the session keys

        @param mrz: The machine readable zone of the passport
        @type mrz: an MRZ object
        @return: A set composed of (KSenc, KSmac, ssc)

        @raise MRZException: I{The mrz length is invalid}: The mrz parameter is not valid.
        @raise BACException: I{Wrong parameter, mrz must be an MRZ object}: The parameter is invalid.
        @raise BACException: I{The mrz has not been checked}: Call the I{checkMRZ} before this method call.
        @raise BACException: I{The sublayer iso7816 is not available}: Check the object init parameter, it takes an iso7816 object
        """

        if isinstance(mrz, MRZ.__class__):
            raise BACException("Wrong parameter, mrz must be an MRZ object instead of {}".format(type(mrz)))

        if not mrz.checked:
            mrz.checkMRZ()

        if isinstance(self._iso7816, ISO7816.__class__):
            raise BACException("The sublayer iso7816 is not available")

        try:
            self.derivationOfDocumentBasicAccesKeys(mrz)
            logging.debug("Request an 8 byte random number from the MRTD's chip")
            rnd_icc = self._iso7816.getChallenge()
            eifd_mifd = self.authentication(rnd_icc)
            hex_eifd_mifd = toHexString(eifd_mifd)
            logging.debug("Send Mutual Authentication")
            eicc_micc = self._iso7816.mutualAuthentication(hex_eifd_mifd)
            return self.sessionKeys(eicc_micc, rnd_icc)
        except ISO7816Exception as e:
            if e.sw1 == 0x63 and e.sw2 == 0x00:
                logging.error("The MRZ is most likely incorrect.")
                raise Exception(e)
        except Exception as msg:
            raise Exception(msg)


    def _computeKeysFromKseed(self, Kseed):
        """
        This function is used during the Derivation of Document Basic Acces Keys.

        @param Kseed: A 16 bytes random value
        @type Kseed: Binary
        @return: A set of two 8 bytes encryption keys
        """

        if DEBUG_CRYPTO: 
            logging.debug("\tKseed: " + toHexString(Kseed))
            logging.debug("Compute Encryption key (Kenc) (c:" + toHexString(BAC.KENC) + ")")
        kenc = self.keyDerivation(Kseed, BAC.KENC)

        if DEBUG_CRYPTO: logging.debug("Compute MAC Computation key (Kmac) (c:" + toHexString(BAC.KMAC) + ")")
        kmac = self.keyDerivation(Kseed, BAC.KMAC)

        return (kenc, kmac)

    def derivationOfDocumentBasicAccesKeys(self, mrz):
        """
        Take the MRZ object, construct the mrz_information out of the MRZ (kmrz),
        generate the Kseed and compute the kenc and Kmac keys from the Kseed.

        @param mrz: The machine readable zone of the passport.
        @type mrz: an MRZ object
        @return: A set of two 8 bytes encryption keys (Kenc, Kmac)
        """
        logging.debug("MRZ: " + str(mrz))

        kmrz = self.mrz_information(mrz)
        kseed = self._genKseed(kmrz)

        logging.debug("Calculate the Basic Acces Keys (Kenc and Kmac) using Appendix 5.1")
        (kenc, kmac) = self._computeKeysFromKseed(kseed)

        self._ksenc = kenc
        self._ksmac = kmac

        return (kenc, kmac)


    def authentication(self, rnd_icc, rnd_ifd=None, kifd=None):
        """
        Construct the command data for the mutual authentication.
            - Request an 8 byte random number from the MRTD's chip (rnd.icc)
            - Generate an 8 byte random (rnd.ifd) and a 16 byte random (kifd)
            - Concatenate rnd.ifd, rnd.icc and kifd (s = rnd.ifd + rnd.icc + kifd)
            - Encrypt it with TDES and the Kenc key (eifd = TDES(s, Kenc))
            - Compute the MAC over eifd with TDES and the Kmax key (mifd = mac(pad(eifd))
            - Construct the APDU data for the mutualAuthenticate command (cmd_data = eifd + mifd)

        @param rnd_icc: The challenge received from the ICC.
        @type rnd_icc: A 8 bytes binary string
        @return: The APDU binary data for the mutual authenticate command
        """
        if DEBUG_CRYPTO: logging.debug("\tRND.ICC: " + toHexString(rnd_icc))

        if not rnd_ifd:
            rnd_ifd = Random.get_random_bytes(8)
        if not kifd:
            kifd = Random.get_random_bytes(16)

        if DEBUG_CRYPTO: 
            logging.debug("Generate an 8 byte random and a 16 byte random")
            logging.debug("\tRND.IFD: " + toHexString(rnd_ifd))
            logging.debug("\tRND.Kifd: " + toHexString(kifd))

        s = rnd_ifd + rnd_icc + kifd
        if DEBUG_CRYPTO: 
            logging.debug("Concatenate RND.IFD, RND.ICC and Kifd")
            logging.debug("\tS: " + toHexString(s))

        tdes = DES3.new(self._ksenc, DES3.MODE_CBC, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        eifd = tdes.encrypt(s)
        if DEBUG_CRYPTO: 
            logging.debug("Encrypt S with TDES key Kenc as calculated in Appendix 5.2")
            logging.debug("\tEifd: " + toHexString(eifd))

        mifd = mac(self._ksmac, pad(eifd))
        if DEBUG_CRYPTO: 
            logging.debug("Compute MAC over eifd with TDES key Kmac as calculated in-Appendix 5.2")
            logging.debug("\tMifd: " + toHexString(mifd))

        cmd_data = eifd + mifd

        self._rnd_ifd = rnd_ifd
        self._kifd = kifd

        return cmd_data

    def sessionKeys(self, data, rnd_icc):
        """
        Calculate the session keys (KSenc, KSmac) and the SSC from the data
        received by the mutual authenticate command.

        @param data: the data received from the mutual authenticate command sent to the chip.
        @type data: a binary string
        @return: A set of two 16 bytes keys (KSenc, KSmac) and the SSC
        """

        if DEBUG_CRYPTO: logging.debug("Decrypt and verify received data and compare received RND.IFD with generated RND.IFD")
        if mac(self._ksmac, pad(data[0:32])) != data[32:]:
            raise Exception("The MAC value is not correct")

        tdes = DES3.new(self._ksenc, DES3.MODE_CBC, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        response = tdes.decrypt(data[0:32])
        response_kicc = response[16:32]
        Kseed = self._xor(self._kifd, response_kicc)
        if DEBUG_CRYPTO: 
            logging.debug("Calculate XOR of Kifd and Kicc")
            logging.debug("\tKseed: " + toHexString(Kseed))

        KSenc = self.keyDerivation(Kseed, BAC.KENC)
        KSmac = self.keyDerivation(Kseed, BAC.KMAC)
        if DEBUG_CRYPTO: 
            logging.debug("Calculate Session Keys (KSenc and KSmac) using Appendix 5.1")
            logging.debug("\tKSenc: " + toHexString(KSenc))
            logging.debug("\tKSmac: " + toHexString(KSmac))

        ssc = rnd_icc[-4:] + self._rnd_ifd[-4:]
        if DEBUG_CRYPTO: 
            logging.debug("Calculate Send Sequence Counter")
            logging.debug("\tSSC: " + toHexString(ssc))

        return (KSenc, KSmac, ssc)


    def _xor(self, kifd, response_kicc):
        kseed = ""
        for i in range(len(toHexString(kifd))):
            kseed += hex(int(toHexString(kifd)[i], 16) ^ int(toHexString(response_kicc)[i], 16))[2:]
        return toBytes(kseed)

    def mrz_information(self, mrz):
        """
        Take an MRZ object and construct the MRZ information out of the MRZ extracted informations:
            - The Document number + Check digit
            - The Date of Birth + CD
            - The Data of Expirity + CD

        @param mrz: An MRZ object
        @type mrz: MRZ object
        @return: the mrz information used for the key derivation
        """
        if isinstance(mrz, MRZ.__class__):
            raise BACException("Bad parameter, must be an MRZ object (" + str(type(mrz)) + ")")

        kmrz = mrz.docNumber[0] + mrz.docNumber[1] + \
            mrz.dateOfBirth[0] + mrz.dateOfBirth[1] + \
            mrz.dateOfExpiry[0] + mrz.dateOfExpiry[1]

        logging.debug("Construct the 'MRZ_information' out of the MRZ")
        logging.debug("\tDocument number: " + mrz.docNumber[0] + "\tCheck digit: " + mrz.docNumber[1])
        logging.debug("\tDate of birth: " + mrz.dateOfBirth[0] + "\t\tCheck digit: " + mrz.dateOfBirth[1])
        logging.debug("\tDate of expiry: " + mrz.dateOfExpiry[0] + "\t\tCheck digit: " + mrz.dateOfExpiry[1])
        logging.debug("\tMRZ_information: " + kmrz)

        return kmrz

    def _genKseed(self, kmrz):
        """
        Calculate the kseed from the kmrz:
            - Calculate a SHA-1 hash of the kmrz
            - Take the most significant 16 bytes to form the Kseed.

        @param kmrz: The MRZ information
        @type kmrz: a string
        @return: a 16 bytes string
        """

        if DEBUG_CRYPTO: logging.debug("Calculate the SHA-1 hash of MRZ_information")

        kseedhash = sha1(kmrz.encode("utf-8"))
        kseed = kseedhash.digest()

        if DEBUG_CRYPTO: 
            logging.debug("\tHsha1(MRZ_information): " + toHexString(kseed))
            logging.debug("Take the most significant 16 bytes to form the Kseed")
            logging.debug("\tKseed: " + toHexString(kseed[:16]))

        return kseed[:16]

    def keyDerivation(self, kseed, c):
        """
        Key derivation from the kseed:
            - Concatenate Kseed and c (c=0 for KENC or c=1 for KMAC)
            - Calculate the hash of the concatenation of kseed and c (h = (sha1(kseed + c)))
            - Adjust the parity bits
            - return the key (The first 8 bytes are Ka and the next 8 bytes are Kb)

        @param kseed: The Kseed
        @type kseed: a 16 bytes string
        @param c: specify if it derives KENC (c=0) of KMAC (c=1)
        @type c: a byte
        @return: Return a 16 bytes key
        """

        if c not in (BAC.KENC, BAC.KMAC):
            raise BACException("Bad parameter (c=0 or c=1)")

        d = kseed + c
        if DEBUG_CRYPTO: 
            logging.debug("\tConcatenate Kseed and c")
            logging.debug("\t\tD: " + toHexString(d))

        h = sha1(d).digest()
        if DEBUG_CRYPTO: 
            logging.debug("\tCalculate the SHA-1 hash of D")
            logging.debug("\t\tHsha1(D): " + toHexString(h))

        Ka = h[:8]
        Kb = h[8:16]

        if DEBUG_CRYPTO: 
            logging.debug("\tExctract Ka and Kb")
            logging.debug("\t\tKa: " + toHexString(Ka))
            logging.debug("\t\tKb: " + toHexString(Kb))

        Ka = self.DESParity(Ka)
        Kb = self.DESParity(Kb)

        if DEBUG_CRYPTO: 
            logging.debug("\tAdjust parity bits")
            logging.debug("\t\tKa: " + toHexString(Ka))
            logging.debug("\t\tKb: " + toHexString(Kb))
            logging.debug("\t\tKey: " + toHexString(Ka) + toHexString(Kb))

        return Ka + Kb


    def DESParity_(self, data):
        adjusted = ''
        for x in range(len(data)):
            y = data[x] & 0xfe
            parity = 0
            for z in range(8):
                parity += y >> z & 1
            adjusted += chr(y + (not parity % 2))
        return adjusted


    def DESParity(self, key):
        adjusted_key = bytearray(key)
        for i in range(len(adjusted_key)):
            adjusted_key[i] = adjusted_key[i] & 0xFE | (bin(adjusted_key[i]).count('1') + 1) % 2
        return bytes(adjusted_key)
