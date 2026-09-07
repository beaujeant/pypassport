from __future__ import annotations

import logging
import os
import time
from typing import Any

from pypassport import ca_manager, der_object_identifier, hex_utils
from pypassport.attacks import mac_traceability
from pypassport.doc9303 import cms, converter, passive_authentication
from pypassport.iso7816 import APDUCommand, ISO7816Exception
from pypassport.utils import to_hex_string


class Fingerprint(object):
    """Run a full automated analysis of an ePassport chip.

    :meth:`analyse` walks the chip end to end and returns a result dict
    describing it: ATR/UID, the data-group inventory and sizes, BAC status and
    document generation, Passive and Active Authentication outcomes, and the
    vulnerability indicators exposed by the C{attacks} modules (MAC
    traceability, AA-before-BAC, block-after-fail, delay security). It drives
    the passport hard — resetting the card and switching the MRZ repeatedly —
    so it expects an :class:`~pypassport.epassport.EPassport` it can own for
    the duration of the run.

    :param epassport: The EPassport to analyse (built with a valid MRZ).
    :param certdir: Optional CSCA certificate directory; when given, Passive
        Authentication is attempted against it.
    :param callback: Optional progress sink with a ``put((None, kind, value))``
        method, where ``kind`` is ``"slfp"`` (a step label) or ``"fp"`` (a
        percentage). Used by the GUI to stream progress.
    """

    def __init__(self, epassport, certdir=None, callback=None):
        self._doc = epassport
        self.curMRZ: str | None = None
        self._pa = passive_authentication.PassiveAuthentication()
        self.callback = callback
        self.doPA = False
        self.csca: ca_manager.CAManager | None = None

        if certdir:
            try:
                self.csca = ca_manager.CAManager(certdir)
                self.doPA = True
            except Exception:
                pass

        self._doc.iso7816.rst_connection()

    def analyse(self):
        res: dict[str, Any] = {}

        res["activeAuthWithoutBac"] = False
        res["macTraceability"] = (False, "N/A")
        res["block_after_fail"] = False
        res["delaySecurity"] = False
        res["select_null"] = "N/A"
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
            self.callback.put((None, "slfp", "Get UID"))
            self.callback.put((None, "fp", 5))

        try:
            res["UID"] = hex_utils.bin_to_hex_rep(self._doc.iso7816.get_uid())
        except Exception:
            logging.error("Could not get the UID")

        # GET ATR
        if self.callback:
            self.callback.put((None, "slfp", "Get ATR"))
            self.callback.put((None, "fp", 10))

        try:
            res["ATR"] = self.get_atr()
        except Exception:
            logging.error("Could not get the ATR")

        # Check if passport blocks after the BAC failed
        if self.callback:
            self.callback.put((None, "slfp", "Check if it blocks after BAC failed"))
            self.callback.put((None, "fp", 15))

        try:
            res["block_after_fail"] = self.block_after_fail()
        except Exception:
            logging.error("Could not verify whether the passport is blocked after a failed BAC")

        # Check if AA is possible before BAC
        if self.callback:
            self.callback.put((None, "slfp", "Check AA before BAC"))
            self.callback.put((None, "fp", 20))

        try:
            res["activeAuthWithoutBac"] = self.check_internal_auth()
        except Exception:
            logging.error("Could not verify whether is it possible to execute active authentication prior to BAC")

        # Check if passport is vulnerable to MAC traceability
        if self.callback:
            self.callback.put((None, "slfp", "Check MAC traceability"))
            self.callback.put((None, "fp", 25))

        try:
            res["macTraceability"] = self.check_mac_traceability()
        except Exception:
            logging.error("Could not verify MAC traceability")

        # Send a SELECT FILE null and check the answer
        if self.callback:
            self.callback.put((None, "slfp", "Check select application null"))
            self.callback.put((None, "fp", 30))

        res["select_null"] = self.select_null()

        # Send a GET CHALLENGE with Le set to 00
        if self.callback:
            self.callback.put((None, "slfp", "Check Get Challenge length 00"))
            self.callback.put((None, "fp", 35))

        try:
            res["getChallengeNull"] = self.send_get_challenge_null()
        except Exception:
            logging.error("Could not send a challenge with an expected length of 0")

        # Check if the secure-messaging is set (BAC)
        # (Get SOD)
        if self.callback:
            self.callback.put((None, "slfp", "Check BAC"))
            self.callback.put((None, "fp", 40))

        try:
            self._doc.iso7816.rst_connection()
            sod: Any | None = None
            sod = self._doc["SOD"]
            if self._doc.iso7816.ciphering is not None:
                res["bac"] = "Done"
        except Exception:
            self._doc.iso7816.rst_connection()
            logging.error("Could not whether secure messaging (BAC) is set")

        # Read SOD body
        if self.callback:
            self.callback.put((None, "slfp", "Read SOD"))
            self.callback.put((None, "fp", 45))

        if sod is not None:
            try:
                res["SOD"] = cms.describe_sod(sod.body)
            except Exception:
                logging.error("Could not parse the SOD structure")

            # Verify SOD body
            if self.callback:
                self.callback.put((None, "slfp", "Verify SOD with CSCA"))
                self.callback.put((None, "fp", 50))

            if self.doPA and self.csca is not None:
                try:
                    pa = passive_authentication.PassiveAuthentication()
                    res["verifySOD"] = pa.verify_sod_and_cds(sod, self.csca)
                except Exception:
                    logging.error("Could not execute passive authentication and verify SOD and CDS")
                    res["verifySOD"] = "No certificate imported verify the SOD"

        # Read DGs and get the file content
        if self.callback:
            self.callback.put((None, "slfp", "Read DGs"))
            self.callback.put((None, "fp", 55))

        self._doc.iso7816.rst_connection()
        data: dict[str, int] = {}
        start = time.time()
        res["EP"]["COM"] = self._doc["COM"]
        for dg in res["EP"]["COM"]["5C"]:
            try:
                res["EP"][converter.to_dg(dg)] = self._doc[dg]
                data[converter.to_dg(dg)] = len(self._doc[dg].file)
            except Exception:
                res["failedToRead"].append(converter.to_dg(dg))
                self._doc.iso7816.rst_connection()
        res["ReadingTime"] = time.time() - start
        lengths = sorted(data.items())
        res["DGs"] = lengths

        # Get hashes
        if self.callback:
            self.callback.put((None, "slfp", "Get hashes of DG files"))
            self.callback.put((None, "fp", 65))

        dgs: list[Any] = []
        for dg in res["EP"]:
            dgs.append(res["EP"][dg])

        res["Integrity"] = self._pa.execute_pa(sod, dgs)
        res["Hashes"] = self._pa._calculate_hashes(dgs)

        try:
            content = self._pa._content
            if content is None:
                raise KeyError("hashAlgorithm")
            res["Algo"] = der_object_identifier.OID[content["hashAlgorithm"]]
        except KeyError:
            logging.error("Hash algorithm not listed")
            res[converter.to_dg(dg)] = "Not defined in hash algorithm list"

        # Check if there is a certificate
        if self.callback:
            self.callback.put((None, "slfp", "Proceed to AA"))
            self.callback.put((None, "fp", 70))

        try:
            certif = self._doc.get_certificate()
            if certif:
                res["DSCertificate"] = certif

                der = cms.load_certificate_der(certif)
                serial_hex = format(cms.certificate_serial(der), "X")
                if len(serial_hex) % 2:
                    serial_hex = "0" + serial_hex
                res["certSerialNumber"] = "serial=" + serial_hex
                res["certFingerprint"] = "SHA1 Fingerprint=" + cms.certificate_sha1_fingerprint(der)
        except Exception:
            logging.error("Could not get certificate")
            self._doc.iso7816.rst_connection()

        # Check if there is a pubKey and the AA
        if self.callback:
            self.callback.put((None, "slfp", "Get public key"))
            self.callback.put((None, "fp", 80))
        try:
            self._doc.iso7816.rst_connection()
            self._doc.do_basic_access_control()
            if self._doc.get_public_key():
                res["pubKey"] = self._doc.get_public_key()
            if self._doc.do_active_authentication():
                res["activeAuth"] = "Done"
        except Exception as msg:
            logging.error("Could not get the public key and/or execute active authentication")
            raise Exception(msg)

        # Define generation
        if self.callback:
            self.callback.put((None, "slfp", "Define the generation"))
            self.callback.put((None, "fp", 85))

        if res["bac"] != "Done":
            res["generation"] = 1

        if res["activeAuth"] == "Done":
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
            self.callback.put((None, "slfp", "Check delay security is implemented"))
            self.callback.put((None, "fp", 90))

        res["delaySecurity"] = self.check_delay_security()

        # Get error message from different wrong APDU
        if self.callback:
            self.callback.put((None, "slfp", "Get a sample of error message"))
            self.callback.put((None, "fp", 95))

        res["Errors"] = self.get_errors_message()

        return res

    def get_atr(self):
        return to_hex_string(self._doc.iso7816.get_atr())

    def check_internal_auth(self):
        self._doc.iso7816.rst_connection()
        rnd_ifd = to_hex_string(list(os.urandom(8)))
        try:
            self._doc.iso7816.internal_authentication(rnd_ifd)
            return True
        except ISO7816Exception:
            return False

    def check_mac_traceability(self):
        self._doc.iso7816.rst_connection()
        try:
            attack = mac_traceability.MacTraceability(self._doc.iso7816)
            attack.set_mrz(str(self.curMRZ))
            return attack.is_vulnerable()
        except Exception:
            return (False, "N/A")

    def check_delay_security(self):
        self._doc.iso7816.rst_connection()
        try:
            self._doc.do_basic_access_control()
            self._doc.iso7816.rst_connection()
            start = time.time()
            self._doc.do_basic_access_control()
            first = time.time() - start
            rndMRZ = "AB12345671ETH0101011M1212318<<<<<<<<<<<<<<04"
            self.curMRZ = self._doc.switch_mrz(rndMRZ)
            for x in range(4):
                try:
                    self._doc.iso7816.rst_connection()
                    self._doc.do_basic_access_control()
                except Exception:
                    pass
            self._doc.switch_mrz(self.curMRZ)
            self._doc.iso7816.rst_connection()
            start = time.time()
            self._doc.do_basic_access_control()
            second = time.time() - start
            if second - first > 0.01:
                return True
            else:
                return False
        except Exception:
            return "N/A"

    def block_after_fail(self):
        self._doc.iso7816.rst_connection()
        rndMRZ = "AB12345671ETH0101011M1212318<<<<<<<<<<<<<<04"
        self.curMRZ = self._doc.switch_mrz(rndMRZ)
        try:
            self._doc.do_basic_access_control()
        except Exception:
            pass
        self._doc.switch_mrz(self.curMRZ)
        try:
            self._doc.do_basic_access_control()
        except Exception:
            return True
        return False

    def select_null(self):
        self._doc.iso7816.rst_connection_raw()
        try:
            toSend = APDUCommand("00", "A4", "00", "00", "", "", "FF")
            return hex_utils.bin_to_hex_rep(self._doc.iso7816.transmit(toSend, "Select File"))
        except ISO7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def send_get_challenge_null(self):
        self._doc.iso7816.rst_connection()
        try:
            toSend = APDUCommand("00", "84", "00", "00", "", "", "01")
            return (True, hex_utils.bin_to_hex_rep(self._doc.iso7816.transmit(toSend, "Get Challenge")))
        except ISO7816Exception as msg:
            return (False, f"SW1:{msg.sw1} SW2:{msg.sw2}")

    def get_errors_message(self):
        test = ["44", "82", "84", "88", "A4", "B0", "B1"]
        errors = dict()
        for ins in test:
            self._doc.iso7816.rst_connection()
            try:
                toSend = APDUCommand("00", ins, "00", "00", "", "", "00")
                self._doc.iso7816.transmit(toSend, "Select File")
                errors[ins] = f"SW1:{114} SW2:{0}"
            except ISO7816Exception as e:
                errors[ins] = f"SW1:{e.sw1} SW2:{e.sw2}"
        return errors
