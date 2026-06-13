# Copyright 2012 Antonin Beaujeant
#
# This file is part of pypassport.
#
# pypassport is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# pypassport is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with pyPassport.
# If not, see <http://www.gnu.org/licenses/>.

import logging
from hashlib import sha1

from pypassport.iso7816 import ISO7816
from pypassport.doc9303 import mrz, bac
from pypassport.doc9303.data_group import readElementaryFile
from pypassport.doc9303.secure_messaging import SecureMessaging
from pypassport.openssl import OpenSSL
from pypassport.utils import toHexString, toBytes

class SignEverythingException(Exception):
    pass

class SignEverything():
    """
    This class allows a user to sign any 64bits message.
    The main method is I{sign}
    """
    def __init__(self, iso7816):
        logging.info("SIGN EVERYTHING ATTACK")
        self._iso7816 = iso7816

        if not isinstance(self._iso7816, ISO7816):
            raise SignEverythingException("The sublayer iso7816 is not available")

        self._iso7816.rstConnection()

        self._bac = bac.BAC(iso7816)
        self._openssl = OpenSSL()

    def sign(self, message_to_sign="1122334455667788", mrz_value=None):
        """
        Get the signature of a 64bits message from the reader.
        In order to prevent ICC cloning, the passport implements an Active Authentication (AA) security.
        The passport signs the 64bits message sent by the reader thanks to its Private key stored in secured memory.
        This method lets the user decide the 64bits and checks (if MRZ set) with the public key if the message has been signed properly

        @params message_to_sign: 64bits message to sign
        @type message_to_sign: String (16 HEX values)

        @return: A set composed of (The signature, Boolean that states if the signature has been checked)
        """
        validated = False
        if mrz_value:
            logging.info("Validation required")
            logging.info("MRZ: {0}".format(mrz_value))
            public_key = self.getPubKey(self._bac, mrz_value)

        # internalAuthentication() accepts the challenge as a hex string and
        # builds the INTERNAL AUTHENTICATE APDU itself, so pass the message
        # straight through. transmit() returns the signature as raw bytes.
        signature = self._iso7816.internalAuthentication(message_to_sign)
        logging.info("Signature: {0}".format(toHexString(signature)))

        if mrz_value:
            logging.info("Check if the signature is correct regarding the public key:")
            data = self._openssl.retrieveSignedData(public_key, signature)
            data_hex = toHexString(data)
            header = data_hex[:2]
            logging.info("\tHeader: {0}".format(header))
            M1 = data_hex[2:214]
            logging.info("\tM1: {0}".format(M1))
            hash_M = data_hex[214:254]
            logging.info("\tHash: {0}".format(hash_M))
            trailer = data_hex[254:256]
            logging.info("\tTrailer: {0}".format(trailer))

            # If using SHA-1
            if header=='6A' and trailer=='BC':
                M = toBytes(M1 + message_to_sign)
                new_hash = sha1(M).digest()
                hash_M_bin = toBytes(hash_M)
                if new_hash==hash_M_bin:
                    logging.info("hash(M|message to sign) == Hash")
                    validated = True

        return (toHexString(signature), validated)

    def getPubKey(self, bac_cp, mrz_value):
        """
        It uses method from pypassport.doc9303.bac in order to authenticate and establish the session keys

        @param bac_cp: A BAC for the authentication and establishment of session keys
        @type bac_cp: A pypassport.doc9303.bac.BAC() object
        @param mrz_value: A MRZ
        @type mrz_value: String value ("PPPPPPPPPPcCCCYYMMDDcSYYMMDDc<<<<<<<<<<<<<<cd")

        @return: The public key (DG15)
        """
        logging.info("Reset connection")
        self._iso7816.rstConnection()

        logging.info("Generate the MRZ object")
        mrz_pass = mrz.MRZ(mrz_value)
        logging.info("Check the MRZ")
        mrz_pass.checkMRZ()

        logging.info("Authentication and establishment of session keys")
        (KSenc, KSmac, ssc) = bac_cp.authenticationAndEstablishmentOfSessionKeys(mrz_pass)
        logging.info("Encryption key: {0}".format(toHexString(KSenc)))
        logging.info("MAC key: {0}".format(toHexString(KSmac)))
        logging.info("Send Sequence Counter: {0}".format(toHexString(ssc)))
        sm = SecureMessaging(KSenc, KSmac, ssc)
        self._iso7816.ciphering = sm

        logging.info("Get public key")
        dg15 = readElementaryFile("DG15", self._iso7816)
        logging.info("Public key: {0}".format(toHexString(dg15.body)))
        return dg15.body


