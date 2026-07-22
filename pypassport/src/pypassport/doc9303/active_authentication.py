import hashlib
import logging
from hashlib import sha1

from Crypto import Random
from ecdsa import BadSignatureError, VerifyingKey
from ecdsa.util import sigdecode_der, sigdecode_string
from pyasn1.codec.der import decoder

from pypassport.asn1 import SubjectPublicKeyInfo
from pypassport import hex_utils
from pypassport.der_object_identifier import OID
from pypassport.doc9303 import cms
from pypassport.doc9303 import data_group
from pypassport.doc9303.security_info import parse_security_infos
from pypassport.utils import to_hex_string


# id-icao-mrtd-security-aaProtocolObject (ActiveAuthenticationInfo, DG14).
_AA_INFO_OID = "2.23.136.1.1.5"

# ecdsa-with-SHA* signature OIDs -> hashlib constructor, used to pick the AA
# hash from DG14's ActiveAuthenticationInfo.
_AA_SIG_OID_HASHES = {
    "1.2.840.10045.4.1": hashlib.sha1,
    "1.2.840.10045.4.3.1": hashlib.sha224,
    "1.2.840.10045.4.3.2": hashlib.sha256,
    "1.2.840.10045.4.3.3": hashlib.sha384,
    "1.2.840.10045.4.3.4": hashlib.sha512,
}


class ActiveAuthenticationException(Exception):
    pass


class ActiveAuthentication:
    """
    This class implements the Active Authentication protocol.
    The main method is I{execute_aa} that returns True if the verification is ok or False.
    """

    def __init__(self, iso7816):
        """
        @param iso7816: a valid iso7816 object
        @type iso7816: doc9303
        """
        self._iso7816 = iso7816

        self.RND_IFD = None
        self.F = None
        self.T = None
        self.decryptedSignature = None
        self.D = None
        self.D_ = None
        self.M1 = None
        self.M_ = None

        self._dg15 = None

    def execute_aa(self, dg15, dg14=None):
        """
        Perform the Active Authentication protocol.

        Supports both signature schemes ICAO Doc 9303 allows for AA:

          - RSA with ISO/IEC 9796-2 Digital Signature scheme 1 (message
            recovery), the classic variant.
          - ECDSA, used by passports whose AA key is on an elliptic curve
            (e.g. the Brainpool curves common in EU documents).

        The scheme is detected from the public key stored in DG15.

        @param dg15: An initialized DataGroup15 object holding the AA public key.
        @type dg15: dataGroup15
        @param dg14: An optional DataGroup14 object. For ECDSA keys its
            ActiveAuthenticationInfo selects the signature hash; when it is
            absent the hash matching the curve size is used instead.
        @return: True if the authentication succeeded, else False.
        @rtype: Boolean
        @raise ActiveAuthenticationException: If the Active Authentication is not supported (The DG15 is not found or the hash algo is not supported).
        @raise ActiveAuthenticationException: If the parameter is not set or is invalid.
        @raise ActiveAuthenticationException: If the public key cannot be recovered from the DG15.
        @raise ActiveAuthenticationException: If the DG15 is invalid and the signature cannot be verified.
        """
        self._dg15 = dg15
        ec_key = self._load_ec_public_key(dg15.body)
        if ec_key is not None:
            return self._execute_aa_ecdsa(ec_key, dg14)
        return self._execute_aa_rsa(dg15)

    def _execute_aa_rsa(self, dg15):
        """Active Authentication with an RSA key (ISO/IEC 9796-2 scheme 1)."""
        self.RND_IFD = self._gen_random(8)
        hex_rnd_ifd = to_hex_string(self.RND_IFD)
        self.signature = self._iso7816.internal_authentication(hex_rnd_ifd)
        self.F = self._decrypt_signature(dg15.body, self.signature)

        (hash_fn, hashSize, offset) = self._get_hash_algo(self.F)
        self.D = self._extract_digest(self.F, hashSize, offset)
        self.M1 = self._extract_m1(self.F, hashSize, offset)

        self.M_ = self.M1 + self.RND_IFD

        logging.debug("Concatenate M1 with known M2")
        logging.debug("\tM*: " + hex_utils.bin_to_hex_rep(self.M_))

        self.D_ = self._hash(hash_fn, self.M_)

        logging.debug("Compare D and D*")
        logging.debug("\t" + str(self.D == self.D_))

        return self.D == self.D_

    def _execute_aa_ecdsa(self, ec_key, dg14):
        """Active Authentication with an ECDSA key.

        The chip signs the 8-byte challenge RND.IFD and returns a plain r||s
        signature (some chips DER-encode it). We verify it against the DG15
        public key, trying the hash chosen from DG14 / the curve size first.
        """
        self.RND_IFD = self._gen_random(8)
        self.signature = self._iso7816.internal_authentication(to_hex_string(self.RND_IFD))
        challenge = bytes(self.RND_IFD)
        signature = bytes(self.signature)

        logging.debug("Active Authentication (ECDSA) on curve %s", ec_key.curve.name)
        for hash_fn in self._aa_ecdsa_hashes(ec_key, dg14):
            for sigdecode in (sigdecode_string, sigdecode_der):
                try:
                    ec_key.verify(signature, challenge, hashfunc=hash_fn, sigdecode=sigdecode, allow_truncate=True)
                    logging.debug("ECDSA AA verified (hash=%s)", getattr(hash_fn, "__name__", hash_fn))
                    return True
                except BadSignatureError:
                    continue
                except Exception:
                    # Wrong signature encoding for this sigdecode, or a digest
                    # too long for the curve — try the next combination.
                    continue
        logging.debug("ECDSA AA: signature did not verify")
        return False

    @staticmethod
    def _load_ec_public_key(spki_der):
        """Return an ecdsa VerifyingKey if DG15 holds an EC key, else None.

        An RSA SubjectPublicKeyInfo makes ``from_der`` raise, so RSA passports
        fall through to the RSA path.
        """
        try:
            return VerifyingKey.from_der(spki_der)
        except Exception:
            return None

    def _aa_ecdsa_hashes(self, ec_key, dg14):
        """Ordered, de-duplicated hash candidates for ECDSA AA verification.

        DG14's ActiveAuthenticationInfo is authoritative; the curve-size
        convention is next; a small set of common hashes is a final safety net
        so a non-conventional chip still verifies.
        """
        candidates = [
            self._aa_hash_from_dg14(dg14),
            self._hash_for_curve(ec_key),
            hashlib.sha256,
            hashlib.sha384,
            hashlib.sha512,
            hashlib.sha224,
            hashlib.sha1,
        ]
        ordered = []
        for h in candidates:
            if h is not None and h not in ordered:
                ordered.append(h)
        return ordered

    @staticmethod
    def _aa_hash_from_dg14(dg14):
        """Return the hash named by DG14's ActiveAuthenticationInfo, or None."""
        if dg14 is None:
            return None
        try:
            for info in parse_security_infos(dg14.body):
                if info.get("protocol_oid") == _AA_INFO_OID:
                    signature_oid = info.get("signature_algorithm_oid")
                    if isinstance(signature_oid, str):
                        return _AA_SIG_OID_HASHES.get(signature_oid)
        except Exception:
            return None
        return None

    @staticmethod
    def _hash_for_curve(ec_key):
        """The SHA matching the curve's field size (ICAO/TR-03111 convention)."""
        bits = ec_key.curve.order.bit_length()
        if bits <= 160:
            return hashlib.sha1
        if bits <= 224:
            return hashlib.sha224
        if bits <= 256:
            return hashlib.sha256
        if bits <= 384:
            return hashlib.sha384
        return hashlib.sha512

    def _gen_random(self, size):
        rnd_ifd = Random.get_random_bytes(size)
        logging.debug("Generate an 8 byte random")
        logging.debug("\tRND.IFD: " + hex_utils.bin_to_hex_rep(rnd_ifd))
        return rnd_ifd

    def get_pub_key(self, dg15):
        """
        Retrieve the public key in PEM format from the dataGroup15

        @return: A PEM representation of the public key
        @rtype: A string
        @raise ActiveAuthenticationException: I{The parameter type is not valid, must be a dataGroup15 object}: The parameter dg15 is not set or is invalid.
        """

        if not isinstance(dg15, data_group.DataGroup15):
            raise ActiveAuthenticationException("The parameter type is not valid, must be a dataGroup15 object")

        return cms.public_key_to_pem(dg15.body)

    def _decrypt_signature(self, pubK, signature):
        data = cms.rsa_recover(pubK, signature)
        logging.debug("Decrypt the signature with the public key")
        logging.debug("\tF: " + hex_utils.bin_to_hex_rep(data))

        return data

    def _hash(self, hash_fn, data):
        digest = hash_fn(data).digest()

        logging.debug("Calculate digest of M*")
        logging.debug("\tD*: " + hex_utils.bin_to_hex_rep(digest))

        return digest

    def _get_hash_algo(self, sig):
        if sig[-1] == 0xBC:
            self.T = sig[-1]
            hash_fn = sha1
            offset = -1
        elif sig[-1] == 0xCC:
            raise ActiveAuthenticationException("Explicit ISO 9796-2 hash trailers are not supported")
        else:
            raise ActiveAuthenticationException("Unknow hash algorithm")

        logging.debug("Determine hash algorithm by trailer T*")
        logging.debug("\tT: " + hex_utils.bin_to_hex_rep(self.T))

        # Find out the hash size
        hashSize = len(hash_fn(b"test").digest())

        return (hash_fn, hashSize, offset)

    def _extract_digest(self, sig, hashSize, offset):
        digest = sig[offset - hashSize : offset]

        logging.debug("Extract digest:")
        logging.debug("\tD: " + hex_utils.bin_to_hex_rep(digest))

        return digest

    def _extract_m1(self, sig, hashSize, offset):
        M1 = sig[1 : offset - hashSize]

        logging.debug("Extract M1:")
        logging.debug("\tM1: " + hex_utils.bin_to_hex_rep(M1))

        return M1

    def __str__(self):
        spec = self._asn1_parse()
        return spec.prettyPrint()

    def algorithm(self, dg15):
        """
        Return the algorithm name used to store the signature
        @return: A string from the OID dictionary.
        @raise ActiveAuthenticationException: I{Unsupported algorithm}: The algorithm does not exist in the OID enumeration.
        @raise ActiveAuthenticationException: I{The parameter type is not valid, must be a dataGroup15 object}: The parameter dg15 is not set or is invalid.
        """
        if not isinstance(dg15, data_group.DataGroup15):
            raise ActiveAuthenticationException("The parameter type is not valid, must be a dataGroup15 object")
        algo = ""
        try:
            spec = self._asn1_parse()
            algo = spec.getComponentByName("algorithm").getComponentByName("algorithm").prettyPrint()
            return OID[algo]
        except KeyError:
            raise ActiveAuthenticationException("Unsupported algorithm: " + algo)
        except Exception as msg:
            raise ActiveAuthenticationException("Active Authentication not supported: ", msg)

    def _asn1_parse(self):
        if self._dg15 is not None:
            certType = SubjectPublicKeyInfo()
            return decoder.decode(self._dg15.body, asn1Spec=certType)[0]
        return ""
