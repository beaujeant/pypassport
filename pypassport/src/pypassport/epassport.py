import os
import logging
from pypassport.doc9303 import converter
from pypassport.doc9303 import securemessaging
from pypassport.doc9303.mrz import MRZ
from pypassport.doc9303.bac import BAC
from pypassport.doc9303.pace import PACE
from pypassport.doc9303.datagroup import readElementaryFile, ElementaryFileException, DataGroupDump
from pypassport.doc9303.activeauthentication import ActiveAuthentication, ActiveAuthenticationException
from pypassport.doc9303.passiveauthentication import PassiveAuthentication, PassiveAuthenticationException
from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport import ca_manager
from pypassport.openssl import OpenSSL, OpenSSLException
from smartcard.Exceptions import NoCardException


class EPassportException(Exception):
    pass


class DataGroupException(Exception):
    pass


class EPassport(dict):
    """
    High-level class encapsulating communication with an ePassport chip.

    Implemented as a dictionary: data groups are read on first access and
    cached. Supports BAC/PACE secure messaging, active authentication, and
    passive authentication.

    @param reader: A reader object (RFID reader) or a path string (simulator).
    @param epMrz: The passport MRZ string or tuple used for BAC key derivation.
    """

    def __init__(self, reader, epMrz=None):
        """
        Initialise the ePassport object.

        @param reader: A reader object or path to dump files for the simulator.
        @param epMrz: MRZ string/tuple. Required for BAC; optional otherwise.
        @raise EPassportException: If the MRZ is invalid, no passport is
            present, or the chip does not contain an eMRTD applet.
        """

        if epMrz:
            self._mrz = MRZ(epMrz)
            if not self._mrz.checkMRZ():
                raise EPassportException("Invalid MRZ")
        else:
            self._mrz = None

        try:
            reader.connect()
        except NoCardException:
            raise EPassportException("No passport present on the reader")

        self.iso7816 = ISO7816(reader)
        self._bac = BAC(self.iso7816)
        self._pace = PACE(self.iso7816, self._mrz)
        self._openSSL = OpenSSL()
        self._aa = ActiveAuthentication(self.iso7816, self._openSSL)
        self._pa = PassiveAuthentication(self._openSSL)
        self._CSCADirectory = None

        # Select eMRTD Dedicated File (DF) with its DF Name (AIS) = A0000002471001
        try:
            self.iso7816.selectDedicatedFile("A0000002471001")
        except ISO7816Exception:
            raise EPassportException("The chip does not contain eMRTD applet")

    @property
    def openSsl(self):
        return self._openSSL.location

    @openSsl.setter
    def openSsl(self, value):
        self._openSSL.location = value

    @property
    def CSCADirectory(self):
        return self._CSCADirectory

    @CSCADirectory.setter
    def CSCADirectory(self, value):
        self._CSCADirectory = ca_manager.CAManager(value)

    def getCSCADirectory(self):
        return self._CSCADirectory

    def setCSCADirectory(self, value, hash=False):
        self._CSCADirectory = ca_manager.CAManager(value)
        if hash:
            logging.debug("Document Signer Certificate hash creation")
            self._CSCADirectory.toHashes()

    def rstConnection(self):
        logging.debug("Reset Connection")
        return self.iso7816.rstConnection()

    def doBasicAccessControl(self):
        """
        Execute the Basic Access Control protocol and set up secure messaging.

        @raise EPassportException: If the MRZ is not initialised.
        """
        logging.info("Basic Access Control: Enabling Secure Messaging")
        if self._mrz is None:
            logging.warning("No MRZ provided")
            raise EPassportException("The object must be initialized with the ePassport MRZ")

        (KSenc, KSmac, ssc) = self._bac.authenticationAndEstablishmentOfSessionKeys(self._mrz)
        sm = securemessaging.SecureMessaging(KSenc, KSmac, ssc)
        self.iso7816.ciphering = sm

    def doActiveAuthentication(self, dg15=None):
        """
        Execute the Active Authentication protocol.

        @return: True if authentication succeeds.
        @raise DataGroupException: If DG15 cannot be read.
        @raise OpenSSLException: On OpenSSL errors.
        @raise ActiveAuthenticationException: On other AA failures.
        """
        logging.info("Active Authentication")
        res = ""
        try:
            if dg15 is None:
                dg15 = self["DG15"]
            res = self._aa.executeAA(dg15)
            return res
        except ElementaryFileException as msg:
            res = msg
            raise DataGroupException(msg)
        except OpenSSLException as msg:
            res = msg
            raise OpenSSLException(str(msg)) from msg
        except Exception as msg:
            res = msg
            raise ActiveAuthenticationException(msg)
        finally:
            logging.debug("Active Authentication: " + str(res))

    def doVerifySODCertificate(self):
        """
        Verify the Document Signer Certificate (first part of passive auth).

        @raise ElementaryFileException: If the SOD cannot be read.
        @raise PassiveAuthenticationException: On PA configuration errors.
        @raise OpenSSLException: On OpenSSL errors.
        """
        res = ""
        try:
            sod = self.readSod()
            res = self._pa.verifySODandCDS(sod, self.CSCADirectory)
            return res
        except ElementaryFileException as msg:
            res = msg
            raise ElementaryFileException(msg)
        except PassiveAuthenticationException as msg:
            res = msg
            raise PassiveAuthenticationException(msg)
        except OpenSSLException as msg:
            res = msg
            raise OpenSSLException(msg)
        finally:
            logging.debug("Document Signer Certificate verification: " + str(res))

    def doVerifyDGIntegrity(self, dgs=None):
        """
        Verify data group integrity (second part of passive auth).

        @raise ElementaryFileException: If a data group cannot be read.
        @raise PassiveAuthenticationException: On PA configuration errors.
        @raise OpenSSLException: On OpenSSL errors.
        """
        res = None
        try:
            sod = self.readSod()
            if dgs is None:
                dgs = self.readDataGroups()
            res = self._pa.executePA(sod, dgs)
            return res
        except ElementaryFileException as msg:
            res = msg
            raise ElementaryFileException(msg)
        except PassiveAuthenticationException as msg:
            res = msg
            raise PassiveAuthenticationException(msg)
        except OpenSSLException as msg:
            res = msg
            raise OpenSSLException(msg)
        except Exception as msg:
            res = msg
            logging.error("Data group integrity verification failed: " + str(msg))
        finally:
            logging.debug("Data Groups integrity verification: " + str(res))

    def doPACE(self):
        PWD_MRZ = bytes([0x01])
        PWD_CAN = bytes([0x02])
        PWD_PIN = bytes([0x03])
        CHAT = b"\x06\x09\x04\x00\x7F\x00\x07\x03\x01\x02\x02\x53\x05\x00\x00\x00\x01\x10"
        oid, domain = self._pace.getPACEInfo(self["DG14"].body)
        self._pace.performPACE(oid, PWD_MRZ, domain_params=domain, chat=CHAT)

    def readSod(self):
        """
        Read the Security Object file (SOD).

        @return: A SOD object.
        """
        return self["SecurityData"]

    def readCom(self):
        """
        Read the Common file and return the list of data groups present.

        @return: A list of data group tag strings (e.g. ["DG1", "DG2", ...]).
        """
        dg_list = []
        for tag in self["Common"]["5C"]:
            dg_list.append(converter.toDG(tag))
        return dg_list

    def readDataGroups(self):
        """
        Read all data groups listed in the Common file (DG1..DG15).

        @return: A list of data group objects successfully read.
        """
        dg_list = []
        for dg in self["Common"]["5C"]:
            try:
                dg_list.append(self[dg])
            except Exception:
                self.iso7816.rstConnection()
        return dg_list

    def readPassport(self):
        """
        Read every file in the passport (COM, DG1..DG15, SOD).

        @return: This EPassport instance (dict populated with all DGs).
        """
        logging.debug("Reading Passport")
        self.readCom()
        self.readDataGroups()
        self.readSod()
        return self

    # Dict overwriting
    def __getitem__(self, tag):
        """
        Return the data group object for the given tag, reading it if necessary.

        If a 'Security Status Not Satisfied' error is returned and secure
        messaging is not yet active, BAC is performed automatically and the
        read is retried.

        @param tag: A tag string such as "DG1", "Common", "SecurityData", etc.
        @return: The parsed data group object, or None if it could not be read.
        @raise ElementaryFileException: If the tag is unknown.
        """
        try:
            tag = converter.toTAG(tag)
        except KeyError:
            raise ElementaryFileException("The data group '" + str(tag) + "' does not exist")

        if tag not in self:
            dg = None
            try:
                dg = readElementaryFile(tag, self.iso7816)
            except ISO7816Exception as e:
                if not self.iso7816.ciphering and e.sw1 == 0x69 and e.sw2 == 0x82:
                    self.doBasicAccessControl()
                    dg = readElementaryFile(tag, self.iso7816)
                else:
                    logging.error(f"Could not read the DG ({e.data})")
                    dg = None
            except Exception as msg:
                logging.exception(msg)
            if dg:
                self.__setitem__(dg.tag, dg)
                return dg
            else:
                return None
        else:
            return super(EPassport, self).__getitem__(tag)

    def __iter__(self):
        """Iterate over all passport files, reading them first if necessary."""
        self.readPassport()
        return super(EPassport, self).__iter__()

    def getSignatures(self):
        """
        Return a list of signatures from DG7 in binary format.

        @return: A list of binary strings.
        """
        tmp = []
        try:
            dg7 = self["DG7"]
            for tag in ["5F43"]:
                if tag in dg7:
                    for x in dg7[tag]:
                        tmp.append(x)
        except Exception:
            pass
        return tmp

    def getFaces(self):
        """
        Return a list of face images from DG2 in binary format.

        @return: A list of binary strings.
        """
        dg2 = self["DG2"]
        tmp = []
        try:
            cpt = 1
            for A in dg2:
                if A == "A" + str(cpt):
                    cpt += 1
                    for tag in ["5F2E", "7F2E"]:
                        if tag in dg2[A]:
                            tmp.append(dg2[A][tag])
        except Exception:
            pass
        return tmp

    def getCertificate(self):
        """
        Extract the Document Signer certificate from the SOD.

        @return: The certificate in human-readable format, or None on error.
        """
        try:
            return self._pa.getCertificate(self.readSod())
        except Exception:
            return None

    def getPublicKey(self):
        """
        Extract the Active Authentication public key from DG15.

        @return: The public key in human-readable format, or None on error.
        """
        try:
            return self._aa.getPubKey(self["DG15"])
        except Exception:
            return None

    def dump(self, directory=os.path.expanduser('~'), format="GRT", extension=".bin"):
        """
        Dump ePassport content to disk, including faces, signatures, the DG15
        public key, and the Document Signer Certificate.

        @param directory: Target directory (default: user home directory).
        @param format: File naming format (see the conversion module).
        @param extension: File extension for data group dumps.
        """
        dgd = DataGroupDump(directory, extension)
        dgd.dump(self, format)

        cpt = 0
        for sig in self.getSignatures():
            dgd.dumpData(sig, "signature" + str(cpt) + ".jpg")
            cpt += 1

        cpt = 0
        for face in self.getFaces():
            dgd.dumpData(face, "face" + str(cpt) + ".jpg")
            cpt += 1

        dgd.dumpData(self.getPublicKey(), "DG15PubKey.pk")
        dgd.dumpData(self.getCertificate(), "DocumentSigner.cer")

    def _logFct(self, name, msg):
        logging.debug(msg, name)

    def switchMRZ(self, newMRZ):
        currentMRZ = self._mrz
        self._mrz = MRZ(newMRZ)
        if not self._mrz.checkMRZ():
            raise EPassportException("Invalid MRZ")
        return str(currentMRZ)
