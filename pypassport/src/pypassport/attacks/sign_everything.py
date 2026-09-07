import logging
from hashlib import sha1

from pypassport.doc9303 import bac, cms, mrz
from pypassport.doc9303.data_group import read_elementary_file
from pypassport.doc9303.secure_messaging import SecureMessaging
from pypassport.hex_utils import bin_to_hex_rep, hex_rep_to_bin
from pypassport.iso7816 import ISO7816


class SignEverythingException(Exception):
    pass


class SignEverything:
    """
    Use the passport's Active Authentication as a signing oracle.

    Active Authentication makes the chip sign an 8-byte challenge chosen by the
    reader with the private key bound to the chip. Because the reader fully
    controls that challenge, the chip will sign *any* 64-bit value presented to
    it. The main method is L{sign}.
    """

    def __init__(self, iso7816):
        self._iso7816 = iso7816

        if not isinstance(self._iso7816, ISO7816):
            raise SignEverythingException("The sublayer iso7816 is not available")

        self._iso7816.rst_connection()
        self._bac = bac.BAC(iso7816)

    def sign(self, message_to_sign="1122334455667788", mrz_value=None):
        """
        Get the chip's signature over an 8-byte (64-bit) message.

        To prevent cloning, the passport implements Active Authentication (AA):
        the chip signs the 8-byte challenge sent by the reader using the private
        key held in secure memory. This method lets the caller pick that
        challenge and, when an MRZ is supplied, verifies the returned signature
        against the public key in DG15.

        @param message_to_sign: 64-bit message to sign (16 hex characters).
        @type message_to_sign: String
        @param mrz_value: Optional MRZ; when set the signature is verified
            against DG15 (which requires a BAC to read DG15).
        @type mrz_value: String

        @return: A tuple (signature as hex string, bool stating whether the
            signature was verified against the public key).
        """
        if len(message_to_sign) != 16:
            raise SignEverythingException("The message to sign must be 64 bits (16 hex characters)")

        public_key = None
        if mrz_value:
            logging.info("Validation required, MRZ: %s", mrz_value)
            public_key = self.get_pub_key(self._bac, mrz_value)

        # internal_authentication() expects the challenge as a hex string and
        # returns the raw signature bytes.
        signature = self._iso7816.internal_authentication(message_to_sign)
        logging.info("Signature: %s", bin_to_hex_rep(signature))

        validated = False
        if public_key is not None:
            validated = self._verify(public_key, signature, message_to_sign)

        return (bin_to_hex_rep(signature), validated)

    def _verify(self, public_key, signature, message_to_sign):
        """Recover the ISO 9796-2 message from the signature and check it."""
        data_hex = bin_to_hex_rep(cms.rsa_recover(public_key, signature))
        header = data_hex[:2]
        M1 = data_hex[2:214]
        hash_M = data_hex[214:254]
        trailer = data_hex[254:256]
        logging.debug("Header: %s  Trailer: %s", header, trailer)

        # Trailer 0xBC selects SHA-1 (single-byte trailer, ISO 9796-2).
        if header == "6A" and trailer == "BC":
            M = hex_rep_to_bin(M1 + message_to_sign)
            if sha1(M).digest() == hex_rep_to_bin(hash_M):
                logging.info("Signature verified: hash(M1 | message) == recovered hash")
                return True
        logging.info("Signature could not be verified against the public key")
        return False

    def get_pub_key(self, bac_cp, mrz_value):
        """
        Establish a BAC and read the Active Authentication public key (DG15).

        @param bac_cp: A BAC object used to authenticate and establish session keys.
        @type bac_cp: pypassport.doc9303.bac.BAC
        @param mrz_value: A MRZ string.
        @type mrz_value: String

        @return: The DG15 body (the DER SubjectPublicKeyInfo).
        """
        self._iso7816.rst_connection()

        mrz_pass = mrz.MRZ(mrz_value)
        if not mrz_pass.check_mrz():
            raise SignEverythingException("Invalid MRZ provided")

        logging.info("Authentication and establishment of session keys")
        (KSenc, KSmac, ssc) = bac_cp.authentication_and_establishment_of_session_keys(mrz_pass)
        self._iso7816.ciphering = SecureMessaging(KSenc, KSmac, ssc)

        dg15 = read_elementary_file("DG15", self._iso7816)
        logging.info("Public key (DG15): %s", bin_to_hex_rep(dg15.body))
        return dg15.body
