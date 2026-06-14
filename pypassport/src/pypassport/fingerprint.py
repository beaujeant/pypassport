import os
import time
import logging

from pypassport.iso7816 import ISO7816Exception, APDUCommand
from pypassport.doc9303 import passive_authentication
from pypassport import ca_manager
from pypassport import pa_crypto
from pypassport import hex_utils
from pypassport.doc9303 import converter
from pypassport.attacks import mac_traceability
from pypassport import der_object_identifier
from pypassport.utils import toHexString

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest


class Fingerprint(object):

    def __init__(self, epassport, certdir=None, callback=None):
        self._doc = epassport
        self.curMRZ = None
        self._pa = passive_authentication.PassiveAuthentication()
        self._certInfo = None
        self.callback = callback
        self.doPA = False

        if certdir:
            try:
                self.csca = ca_manager.CAManager(certdir)
                self.csca.toHashes()
                self.doPA = True
            except Exception:
                pass

        self._doc.iso7816.rstConnection()

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
            res["UID"] = hex_utils.binToHexRep(self._doc.iso7816.getUID())
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
            self._doc.iso7816.rstConnection()
            sod = None
            sod = self._doc["SecurityData"]
            if self._doc.iso7816.ciphering:
                res["bac"] = "Done"
        except Exception:
            self._doc.iso7816.rstConnection()
            logging.error("Could not whether secure messaging (BAC) is set")

        #Read SOD body
        if self.callback:
            self.callback.put((None, 'slfp', "Read SOD"))
            self.callback.put((None, 'fp', 45))

        if sod is not None:
            try:
                res["SOD"] = pa_crypto.asn1_dump(sod.body)
            except Exception:
                logging.error("Could not parse the SOD structure")

            #Verify SOD body
            if self.callback:
                self.callback.put((None, 'slfp', "Verify SOD with CSCA"))
                self.callback.put((None, 'fp', 50))

            if self.doPA:
                try:
                    pa = passive_authentication.PassiveAuthentication()
                    res["verifySOD"] = pa.verifySODandCDS(sod, self.csca)
                except Exception:
                    logging.error("Could not execute passive authentication and verify SOD and CDS")
                    res["verifySOD"] = "No certificate imported verify the SOD"

        #Read DGs and get the file content
        if self.callback:
            self.callback.put((None, 'slfp', "Read DGs"))
            self.callback.put((None, 'fp', 55))

        self._doc.iso7816.rstConnection()
        data = {}
        start = time.time()
        res["EP"]["Common"] = self._doc["Common"]
        for dg in res["EP"]["Common"]["5C"]:
            try:
                res["EP"][converter.toDG(dg)] = self._doc[dg]
                data[converter.toDG(dg)] = len(self._doc[dg].file)
            except Exception:
                res["failedToRead"].append(converter.toDG(dg))
                self._doc.iso7816.rstConnection()
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

        # Passive Authentication / hash comparison needs a readable SOD. When
        # BAC failed (or the SOD could not be read) sod is None and executePA
        # would raise; keep the rest of the report intact instead of aborting.
        try:
            res["Integrity"] = self._pa.executePA(sod, dgs)
            res["Hashes"] = self._pa._calculateHashes(dgs)
        except Exception:
            logging.error("Could not verify data-group integrity (passive authentication)")

        try:
            res["Algo"] = der_object_identifier.OID[self._pa._content['hashAlgorithm']]
        except (KeyError, TypeError):
            logging.error("Hash algorithm not listed")

        #Check if there is a certificate
        if self.callback:
            self.callback.put((None, 'slfp', "Proceed to AA"))
            self.callback.put((None, 'fp', 70))

        try:
            certif = self._doc.getCertificate()
            if certif:
                res["DSCertificate"] = certif
                dsc_der = pa_crypto._pem_or_der_to_der(certif)
                res["certSerialNumber"] = pa_crypto.cert_serial(dsc_der)
                res["certFingerprint"] = pa_crypto.cert_sha1_fingerprint(dsc_der)
        except Exception:
            logging.error("Could not get certificate")
            self._doc.iso7816.rstConnection()


        #Check if there is a pubKey and the AA
        if self.callback:
            self.callback.put((None, 'slfp', "Get public key"))
            self.callback.put((None, 'fp', 80))
        try:
            self._doc.iso7816.rstConnection()
            self._doc.doBasicAccessControl()
            if self._doc.getPublicKey():
                res["pubKey"] = self._doc.getPublicKey()
            if self._doc.doActiveAuthentication():
                res["activeAuth"] = "Done"
        except Exception:
            logging.error("Could not get the public key and/or execute active authentication")
            self._doc.iso7816.rstConnection()

        # Define generation
        if self.callback:
            self.callback.put((None, 'slfp', "Define the generation"))
            self.callback.put((None, 'fp', 85))

        # res["bac"] / res["activeAuth"] hold the strings "Done"/"Failed", so
        # compare against "Done" rather than testing truthiness (every
        # non-empty string is truthy).
        if res["bac"] != "Done":
            res["generation"] = 1
        elif res["activeAuth"] == "Done":
            if res["activeAuthWithoutBac"]:
                res["generation"] = 3
            else:
                res["generation"] = 2

            try:
                self._doc["DG7"]
            except Exception:
                res["generation"] = 4
        else:
            res["generation"] = 1


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
        self._doc.iso7816.rstConnection()
        rnd_ifd = toHexString(list(os.urandom(8)))
        try:
            self._doc.iso7816.internalAuthentication(rnd_ifd)
            return True
        except ISO7816Exception:
            return False

    def checkMACTraceability(self):
        self._doc.iso7816.rstConnection()
        try:
            # MacTraceability needs a valid MRZ to derive the BAC keys for the
            # legitimate message/MAC pair. curMRZ is set to the genuine MRZ by
            # blockAfterFail() earlier in analyse(); a missing/invalid value
            # raises in the constructor and we fall back to "N/A".
            attack = mac_traceability.MacTraceability(self._doc.iso7816, str(self.curMRZ))
            return attack.isVulnerable()
        except Exception:
            return (False, "N/A")

    def checkDelaySecurity(self):
        self._doc.iso7816.rstConnection()
        try:
            self._doc.doBasicAccessControl()
            self._doc.iso7816.rstConnection()
            start = time.time()
            self._doc.doBasicAccessControl()
            first = time.time() - start
            rndMRZ = "AB12345671ETH0101011M1212318<<<<<<<<<<<<<<04"
            self.curMRZ = self._doc.switchMRZ(rndMRZ)
            for x in range(4):
                try:
                    self._doc.iso7816.rstConnection()
                    self._doc.doBasicAccessControl()
                except Exception:
                    pass
            self._doc.switchMRZ(self.curMRZ)
            self._doc.iso7816.rstConnection()
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
        self._doc.iso7816.rstConnection()
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
        self._doc.iso7816.rstConnectionRaw()
        try:
            toSend = APDUCommand("00", "A4", "00", "00", "", "", "FF")
            return hex_utils.binToHexRep(self._doc.iso7816.transmit(toSend, "Select File"))
        except ISO7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def sendGetChallengeNull(self):
        self._doc.iso7816.rstConnection()
        try:
            toSend = APDUCommand("00", "84", "00", "00", "", "", "01")
            return (True, hex_utils.binToHexRep(self._doc.iso7816.transmit(toSend, "Get Challenge")))
        except ISO7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def getErrorsMessage(self):
        test = ["44", "82", "84", "88", "A4", "B0", "B1"]
        errors = dict()
        for ins in test:
            self._doc.iso7816.rstConnection()
            try:
                toSend = APDUCommand("00", ins, "00", "00", "", "", "00")
                self._doc.iso7816.transmit(toSend, "Select File")
                errors[ins] = f"SW1:{114} SW2:{0}"
            except ISO7816Exception as e:
                errors[ins] = f"SW1:{e.sw1} SW2:{e.sw2}"
        return errors
