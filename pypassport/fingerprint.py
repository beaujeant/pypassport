import os
import time
import logging

from pypassport.iso7816 import Iso7816Exception
from pypassport.doc9303 import passiveauthentication
from pypassport import apdu, camanager
from pypassport import hexfunctions
from pypassport.doc9303 import converter
from pypassport.attacks import macTraceability
from pypassport import derobjectidentifier

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString


class Fingerprint(object):

    def __init__(self, epassport, certdir=None, callback=None):
        self._doc = epassport
        self.curMRZ = None
        self._comm = self._doc.getCommunicationLayer()
        self._pa = passiveauthentication.PassiveAuthentication(epassport)
        self._certInfo = None
        self.callback = callback
        self.doPA = False

        if certdir:
            try:
                self.csca = camanager.CAManager(certdir)
                self.csca.toHashes()
                self.doPA = True
            except Exception:
                pass

        self._comm.rstConnection()

    def getCertInfo(self):
        return self._certInfo

    def setCertInfo(self, value):
        self._certInfo = value

    def analyse(self):
        res = {}

        res["activeAuthWithoutBac"] = False
        res["macTraceability"] = (False, "N/A")
        res["blockAfterFail"] = False
        res["delaySecurity"] = False
        res["selectNull"] = "N/A"
        res["getChallengeNull"] = "N/A"
        res["bac"] = "Failed"
        res["verifySOD"] = "No certificate imported"
        res["DSCertificate"] = "Document Signer Certificate: N/A"
        res["pubKey"] = "Private key: N/A"
        res["activeAuth"] = "Failed"
        res["generation"] = 0
        res["certSerialNumber"] = "N/A"
        res["certFingerprint"] = "N/A"
        res["ATR"] = "N/A"
        res["UID"] = "N/A"
        res["DGs"] = "Cannot calculate the DG size"
        res["ReadingTime"] = "N/A"
        res["SOD"] = "N/A"
        res["Algo"] = "N/A"
        res["Integrity"] = "N/A"
        res["Hashes"] = "N/A"
        res["failedToRead"] = list()
        res["EP"] = dict()
        res["Errors"] = dict()


        # GET UID
        if self.callback:
            self.callback.put((None, 'slfp', "Get UID"))
            self.callback.put((None, 'fp', 5))

        try:
            res["UID"] = hexfunctions.binToHexRep(self._comm.getUID())
        except Exception:
            logging.error("Could not get the UID")

        # GET ATR
        if self.callback:
            self.callback.put((None, 'slfp', "Get ATR"))
            self.callback.put((None, 'fp', 10))

        try:
            res["ATR"] = self.getATR()
        except Exception:
            logging.error("Could not get the ATR")

        # Check if passport blocks after the BAC failed
        if self.callback:
            self.callback.put((None, 'slfp', "Check if it blocks after BAC failed"))
            self.callback.put((None, 'fp', 15))

        try:
            res["blockAfterFail"] = self.blockAfterFail()
        except Exception:
            logging.error("Could not verify whether the passport is blocked after a failed BAC")

        # Check if AA is possible before BAC
        if self.callback:
            self.callback.put((None, 'slfp', "Check AA before BAC"))
            self.callback.put((None, 'fp', 20))

        try:
            res["activeAuthWithoutBac"] = self.checkInternalAuth()
        except Exception:
            logging.error("Could not verify whether is it possible to execute active authentication prior to BAC")

        # Check if passport is vulnerable to MAC traceability
        if self.callback:
            self.callback.put((None, 'slfp', "Check MAC traceability"))
            self.callback.put((None, 'fp', 25))

        try:
            res["macTraceability"] = self.checkMACTraceability()
        except Exception:
            logging.error("Could not verify MAC traceability")

        # Send a SELECT FILE null and check the answer
        if self.callback:
            self.callback.put((None, 'slfp', "Check select application null"))
            self.callback.put((None, 'fp', 30))

        res["selectNull"] = self.selectNull()

        # Send a GET CHALLENGE with Le set to 00
        if self.callback:
            self.callback.put((None, 'slfp', "Check Get Challenge length 00"))
            self.callback.put((None, 'fp', 35))

        try:
            res["getChallengeNull"] = self.sendGetChallengeNull()
        except Exception:
            logging.error("Could not send a challenge with an expected length of 0")

        #Check if the secure-messaging is set (BAC)
        #(Get SOD)
        if self.callback:
            self.callback.put((None, 'slfp', "Check BAC"))
            self.callback.put((None, 'fp', 40))

        try:
            self._comm.rstConnection()
            sod = None
            sod = self._doc["SecurityData"]
            if self._comm._ciphering:
                res["bac"] = "Done"
        except Exception:
            self._comm.rstConnection()
            logging.error("Could not whether secure messaging (BAC) is set")

        #Read SOD body
        if self.callback:
            self.callback.put((None, 'slfp', "Read SOD"))
            self.callback.put((None, 'fp', 45))

        if sod != None:
            with open('sod', 'wb') as fd:
                fd.write(sod.body)
            f = os.popen("openssl asn1parse -in sod -inform DER -i")
            res["SOD"] = f.read().strip()
            os.remove('sod')

            #Verify SOD body
            if self.callback:
                self.callback.put((None, 'slfp', "Verify SOD with CSCA"))
                self.callback.put((None, 'fp', 50))

            if self.doPA:
                try:
                    pa = passiveauthentication.PassiveAuthentication()
                    res["verifySOD"] = pa.verifySODandCDS(sod, self.csca)
                except Exception:
                    logging.error("Could not execute passive authentication and verify SOD and CDS")
                    res["verifySOD"] = "No certificate imported verify the SOD"

        #Read DGs and get the file content
        if self.callback:
            self.callback.put((None, 'slfp', "Read DGs"))
            self.callback.put((None, 'fp', 55))

        self._comm.rstConnection()
        data = {}
        start = time.time()
        res["EP"]["Common"] = self._doc["Common"]
        for dg in res["EP"]["Common"]["5C"]:
            try:
                res["EP"][converter.toDG(dg)] = self._doc[dg]
                data[converter.toDG(dg)] = len(self._doc[dg].file)
            except Exception:
                res["failedToRead"].append(converter.toDG(dg))
                self._comm.rstConnection()
        res["ReadingTime"] = time.time() - start
        lengths = sorted(data.items())
        res["DGs"] = lengths

        # Get hashes
        if self.callback:
            self.callback.put((None, 'slfp', "Get hashes of DG files"))
            self.callback.put((None, 'fp', 65))

        dgs = list()
        for dg in res["EP"]:
            dgs.append(res["EP"][dg])

        res["Integrity"] = self._pa.executePA(sod, dgs)
        res["Hashes"] = self._pa._calculateHashes(dgs)

        try:
            res["Algo"] = derobjectidentifier.OID[self._pa._content['hashAlgorithm']]
        except KeyError:
            logging.error("Hash algorythm not listed")
            res[converter.toDG(dg)] = "Not defined in hash algorithm list"

        #Check if there is a certificate
        if self.callback:
            self.callback.put((None, 'slfp', "Proceed to AA"))
            self.callback.put((None, 'fp', 70))

        try:
            certif = self._doc.getCertificate()
            if certif:
                res["DSCertificate"] = self._doc.getCertificate()

                f = open("tmp.cer", "w")
                f.write(certif.decode())
                f.close()

                f = os.popen("openssl x509 -in tmp.cer -noout -serial")
                res["certSerialNumber"] = f.read().strip()
                f.close()

                f = os.popen("openssl x509 -in tmp.cer -noout -fingerprint")
                res["certFingerprint"] = f.read().strip()
                f.close()

                os.remove("tmp.cer")
        except Exception:
            logging.error("Could not get certificate")
            self._comm.rstConnection()


        #Check if there is a pubKey and the AA
        if self.callback:
            self.callback.put((None, 'slfp', "Get public key"))
            self.callback.put((None, 'fp', 80))
        try:
            self._comm.rstConnection()
            self._doc.doBasicAccessControl()
            if self._doc.getPublicKey():
                res["pubKey"] = self._doc.getPublicKey()
            if self._doc.doActiveAuthentication():
                res["activeAuth"] = "Done"
        except Exception as msg:
            logging.error("Could not get the public key and/or execute active authentication")
            raise Exception(msg)

        # Define generation
        if self.callback:
            self.callback.put((None, 'slfp', "Define the generation"))
            self.callback.put((None, 'fp', 85))

        if not res["bac"]:
            res["generation"] = 1

        if res["activeAuth"]:
            if res["activeAuthWithoutBac"]:
                res["generation"] = 3
            else:
                res["generation"] = 2

            try:
                self._doc["DG7"]
            except Exception:
                res["generation"] = 4


        # Check if passport implements delay security
        if self.callback:
            self.callback.put((None, 'slfp', "Check delay security is implemented"))
            self.callback.put((None, 'fp', 90))

        res["delaySecurity"] = self.checkDelaySecurity()

        # Get error message from different wrong APDU
        if self.callback:
            self.callback.put((None, 'slfp', "Get a sample of error message"))
            self.callback.put((None, 'fp', 95))

        res["Errors"] = self.getErrorsMessage()

        return res

    def getATR(self):
        cardtype = AnyCardType()
        cardrequest = CardRequest(timeout=1, cardType=cardtype)
        cardservice = cardrequest.waitforcard()

        cardservice.connection.connect()
        return toHexString(cardservice.connection.getATR())

    def checkInternalAuth(self):
        self._comm.rstConnection()
        rnd_ifd = os.urandom(8)
        try:
            self._comm.internalAuthentication(rnd_ifd)
            return (True, hexfunctions.binToHexRep(self._comm.internalAuthentication(rnd_ifd)))
        except Iso7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def checkMACTraceability(self):
        self._comm.rstConnection()
        try:
            attack = macTraceability.MacTraceability(self._comm)
            attack.setMRZ(str(self.curMRZ))
            return attack.isVulnerable()
        except Exception:
            return (False, "N/A")

    def checkDelaySecurity(self):
        self._comm.rstConnection()
        try:
            self._doc.doBasicAccessControl()
            self._comm.rstConnection()
            start = time.time()
            self._doc.doBasicAccessControl()
            first = time.time() - start
            rndMRZ = "AB12345671ETH0101011M1212318<<<<<<<<<<<<<<04"
            self.curMRZ = self._doc.switchMRZ(rndMRZ)
            for x in range(4):
                try:
                    self._comm.rstConnection()
                    self._doc.doBasicAccessControl()
                except Exception:
                    pass
            self._doc.switchMRZ(self.curMRZ)
            self._comm.rstConnection()
            start = time.time()
            self._doc.doBasicAccessControl()
            second = time.time() - start
            if second - first > 0.01:
                return True
            else:
                return False
        except Exception:
            return "N/A"

    def blockAfterFail(self):
        self._comm.rstConnection()
        rndMRZ = "AB12345671ETH0101011M1212318<<<<<<<<<<<<<<04"
        self.curMRZ = self._doc.switchMRZ(rndMRZ)
        try:
            self._doc.doBasicAccessControl()
        except Exception:
            pass
        self._doc.switchMRZ(self.curMRZ)
        try:
            self._doc.doBasicAccessControl()
        except Exception:
            return True
        return False

    def selectNull(self):
        self._comm.rstConnectionRaw()
        try:
            toSend = apdu.CommandAPDU("00", "A4", "00", "00", "", "", "FF")
            return hexfunctions.binToHexRep(self._comm.transmit(toSend, "Select File"))
        except Iso7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def sendGetChallengeNull(self):
        self._comm.rstConnection()
        try:
            toSend = apdu.CommandAPDU("00", "84", "00", "00", "", "", "01")
            return (True, hexfunctions.binToHexRep(self._comm.transmit(toSend, "Get Challenge")))
        except Iso7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def getErrorsMessage(self):
        test = ["44", "82", "84", "88", "A4", "B0", "B1"]
        errors = dict()
        for ins in test:
            self._comm.rstConnection()
            try:
                toSend = apdu.CommandAPDU("00", ins, "00", "00", "", "", "00")
                self._comm.transmit(toSend, "Select File")
                errors[ins] = f"SW1:{114} SW2:{0}"
            except Iso7816Exception as e:
                errors[ins] = f"SW1:{e.sw1} SW2:{e.sw2}".format(e.sw1, e.sw2)
        return errors
