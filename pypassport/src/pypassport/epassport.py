import os
import logging
from pypassport.doc9303 import converter
from pypassport.doc9303 import securemessaging
from pypassport.doc9303.mrz import MRZ
from pypassport.doc9303.bac import BAC
from pypassport.doc9303.pace import PACE
from pypassport.doc9303.datagroup import readElementaryFile, ElementaryFileException
#from pypassport.doc9303.datagroup import DataGroupReader, DataGroupException, DataGroupDump
from pypassport.doc9303.activeauthentication import ActiveAuthentication, ActiveAuthenticationException
from pypassport.doc9303.passiveauthentication import PassiveAuthentication, PassiveAuthenticationException
from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport import camanager
from pypassport.openssl import OpenSSL, OpenSSLException
from smartcard.Exceptions import NoCardException


class EPassportException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class dgException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class EPassport(dict):
    """
    This class is the high level class that encapsulates every mechanism needed to communicate with the passport
    and to validate it.

    This object is implemented as a dictionary.
    When a dataGroup is read, the corresponding object is added inside the object dictionary.

    Example with the DG1 file using the simulator:
    (see the dataGroups.converter for an exaustive conversion list)


    >>> import os
    >>> from pypassport.epassport import *
    >>> from pypassport.iso7816 import *
    >>> p = EPassport(None, "dump.file")
    Select Passport Application
    >>> p["DG1"]
    Reading DG1
    {...}

    You can notice that the DG1 is read only during the first call.

    The passport application is selected during the init phase,
    and the basic access control is done automatically if needed.

    Example using a rfid reader:
    * Detect the reader
    * Init the EPassport class
    * Read the DG1
    * Perform Active Auth
    * Perform Passive Auth (Verification of the SOD Certificate, Verification of the DG integrity)
    * Extract the DS Certificate
    * Extract the DG15 public key
    * Extract the faces from DG2
    * Extract the signature from DG7

    We changed the MRZ informations for privacy reasons, that's why the doctest is not valid.
    Anyway it is not possible for you to test it without the real passport (you do not possess it).
    Just consider it as a trace explaining how to access a real passport.


    >>> from pypassport.epassport import EPassport, mrz
    >>> from pypassport.reader import pcscAutoDetect
    >>> from pypassport.openssl import OpenSSLException
    >>> detect = pcscAutoDetect()
    >>> detect
    (<pypassport.reader.pcscReader object at 0x00CA46F0>, 1, 'OMNIKEY CardMan 5x21-CL 0', 'GENERIC')
    >>> reader = detect[0]
    >>> mrz = MRZ('EHxxxxxx<0BELxxxxxx8Mxxxxxx7<<<<<<<<<<<<<<04')
    >>> mrz.checkMRZ()
    True
    >>> p = EPassport(mrz, reader)
    Select Passport Application
    >>> p["DG1"]
    Reading DG1
    {...}
    >>> p.openSslDirectory = "C:\\OpenSSL\\bin\\openssl"
    >>> p.doActiveAuthentication()
    Reading DG15
    Active Authentication: True
    True
    >>> p.CSCADirectory = 'D:\\workspace\\pypassport\\src\\data\\cert'
    >>> try:
    ...     p.doVerifySODCertificate()
    ... except OpenSSLException, msg:
    ...     print msg
    ...
    /C=BE/O=Kingdom of Belgium/OU=Federal Public Service Foreign Affairs Belgium/CN=DSPKI_BEerror 20 at 0 depth lookup:unable to get local issuer certificate
    >>> try:
    ...     p.doVerifyDGIntegrity()
    ... except pypassport.openssl.OpenSSLException, msg:
    ...     print msg
    ...
    Reading Common
    Reading DG2
    Reading DG7
    Reading DG11
    Reading DG12
    {'DG15': True, 'DG11': True, 'DG12': True, 'DG2': True, 'DG1': True, 'DG7': True}
    >>> p.getCertificate()
    'subject=/C=BE/O=Kingdom of Belgium/OU=Feder...eign Affairs Belgium/CN=CSCAPKI_BE
    -----BEGIN CERTIFICATE-----
    MIIEnDCCAoSgA...IJhypc0=
    -----END CERTIFICATE-----'
    >>> p.getPublicKey()
    'Modulus=D8772AC284BE...8FC508B57AFBD57
    -----BEGIN PUBLIC KEY-----
    MIGdMA0GCSqGSIb3DQEBAQUAA...ck4/FCLV6+9VwIBAw==
    -----END PUBLIC KEY-----'
    >>> p.getFaces()
    ['\x14R\x06\x14\xd3E\x14\xfa\x87C\xff\xd9...']
    >>> p.getSignature()
    ['\x01h\xa4\xa2...\x80?\xff\xd9']
    """

    # TODO: property pr le buffSize de la lecture et pour choisir si FS ou SFID

    def __init__(self, reader, epMrz=None):
        """
        This object provides most of the functionalities described in the EPassport document.
            - The basic access control + secure messaging
            - The active authentication
            - The passive authentication
            - Reading of the various dataGroups

        @param reader: It can be a reader or a path to dumps
        @type reader: A reader object, then it will use the specified rfid reader.
                      A string, then the simulator will read the dumps from the specified url.

        @param mrz: An object representing the passport MRZ.
        @type mrz: An MRZ object
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
        #self._dgReader = DataGroupReader(self.iso7816)
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


    def _getOpenSslDirectory(self):
        return self._openSSL.location


    def _setOpenSslDirectory(self, value):
        self._openSSL.location = value


    def getCSCADirectory(self):
        return self._CSCADirectory


    def setCSCADirectory(self, value, hash=False):
        self._CSCADirectory = camanager.CAManager(value)
        if hash:
            logging.debug("Document Signer Certificate hash creation")
            self._CSCADirectory.toHashes()


    def rstConnection(self):
        logging.debug("Reset Connection")
        return self.iso7816.rstConnection()


    def doBasicAccessControl(self):
        """
        Execute the basic access control protocol and set up the secure messaging.

        @return: A True if the BAC execute correctly
        @raise bacException: If an error occurs during the process
        @raise EPassportException: If the mrz is not initialized.
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
        Execute the active authentication protocol.

        @return: A boolean if the test completes.
        @raise aaException: If the hash algo is not supported or if the AA is not supported.
        @raise openSSLException: See the openssl documentation
        @raise SimIso7816Exception: The AA is not possible with the simulator
        """
        logging.info("Active Autheticiation")
        res = ""
        try:
            if dg15 is None:
                dg15 = self["DG15"]
            res = self._aa.executeAA(dg15)
            return res
        except ElementaryFileException as msg:
            res = msg
            raise dgException(msg)
        except OpenSSLException as msg:
            res = msg
            raise OpenSSLException(msg)
        except Exception as msg:
            res = msg
            raise ActiveAuthenticationException(msg)
        finally:
            logging.debug("Active Authentication: " + str(res))


    def doVerifySODCertificate(self):
        """
        Execute the first part of the passive authentication: The verification of the certificate validity.

        @raise dgException: If the SOD could not be read
        @raise paException: If the object is badly configured
        @raise openSSLException: See the openssl documentation
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
        Execute the second part of the passive authentication: The verification of the dataGroups integrity.

        @raise dgException: If the data groups could not be read
        @raise paException: If the object is badly configured
        @raise openSSLException: See the openssl documentation
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
        Read the security object file of the passport.

        @return: A sod object.
        """
        return self["SecurityData"]


    def readCom(self):
        """
        Read the common file of the passport.

        @return: A list with the data group tags present in the passport.
        """
        list = []
        for tag in self["Common"]["5C"]:
            list.append(converter.toDG(tag))
        return list


    def readDataGroups(self):
        """
        Read the datagroups present in the passport. (DG1..DG15)
        The common and sod files are not read.

        @return: A list of dataGroup objects.
        """
        list = []
        for dg in self["Common"]["5C"]:
            try:
                list.append(self[dg])
            except Exception:
                self.iso7816.rstConnection()
        return list


    def readPassport(self):
        """
        Read every files of the passport (COM, DG1..DG15, SOD)

        @return: A dictionary with every dataGroup objects present in the passport.
        """
        logging.debug("Reading Passport")
        self.readCom()
        self.readDataGroups()
        self.readSod()

        return self

    #Dict overwriting
    def __getitem__(self, tag):
        """
        @param tag: A Valid tag representing a dataGroup
        @type tag: A string
        @return: The datagroup object representing this dataGroup

        @raise DataGroupException: If the tag is not linked to any dataGroup, or if an error occurs during the parsing
        @raise APDUException: If an error occurs during the APDU transmit.

        Try to read the DataGroup specified by the parameter 'tag'.
        If the DG is already read, the DG is directly returned,
        else the DG is read then returned

        If there is a Security status not satisfied error,
        the mutual authentication is run.
        If there is no error during the mutualAuth, the APDU is sent again else,
        the error is propagated: there surely is an error in the MRZ field value

        Please refer to ICAO Doc9303 Part 1 Volume 2, p III-28 for the complete
        DataGroup <-> Tag correspondance
        or have a look to the pypassport.datagroup.converter.py file
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
                    dgFile = None
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
        """
        Implementation of the object iterator method.
        Read every passport files.
        """
        self.readPassport()
        return super(EPassport, self).__iter__()

    def getSignatures(self):
        """
        Return a list with the signatures contained in the DG7 in binary format.
        @return: A list of binary string
        @rtype: A list
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
        Return a list with the images contained in the DG2 in binary format.
        @return: A list of binary string
        @rtype: A list
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
        Extract the Document Signer certificate from the SOD
        @return: The certificate in a human readable format
        @rtype: A string
        """
        try:
            return self._pa.getCertificate(self.readSod())
        except Exception:
            return None

    def getPublicKey(self):
        """
        Extract the Active Auth public key from the DG15
        @return: The public key in a human readable format
        @rtype: A string
        """
        try:
            return self._aa.getPubKey(self["DG15"])
        except Exception:
            return None

    def dump(self, directory=os.path.expanduser('~'), format="GRT", extension = ".bin"):
        """
        Dump the ePassport content on disk as well as the faces ans signatures in jpeg,
        the DG15 public key and the Document Signer Certificate.

        By default, the files are stored in the user directory (~) with the Golden Reader Tool naming format

        @param directory: Target directory
        @param format: File naming format (see the conversion module)
        @param extension: File extension
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

    CSCADirectory = property(getCSCADirectory, setCSCADirectory)
    openSsl = property(_getOpenSslDirectory, _setOpenSslDirectory, None, None)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
