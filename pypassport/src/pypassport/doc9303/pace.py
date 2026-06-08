"""
PACE (Password Authenticated Connection Establishment) for ICAO 9303 ePassports.

Implements the Generic Mapping (GM) variant with ECDH over Brainpool P-256-r1
and AES session keys, per BSI TR-03110 Part 2 §3.4 and Part 3 Appendix A.

Supported algorithm OIDs
-------------------------
id-PACE-ECDH-GM-AES-CBC-CMAC-128  0.4.0.127.0.7.2.2.4.2.2
id-PACE-ECDH-GM-AES-CBC-CMAC-192  0.4.0.127.0.7.2.2.4.2.3
id-PACE-ECDH-GM-AES-CBC-CMAC-256  0.4.0.127.0.7.2.2.4.2.4

References
----------
https://github.com/tsenger/pypace
https://github.com/AndyQ/NFCPassportReader/blob/main/Sources/NFCPassportReader/PACEHandler.swift
https://github.com/jllarraz/AndroidPassportReader/...
"""

import hashlib
import logging

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from ecdsa.ellipticcurve import CurveFp, Point
from pyasn1.codec.der.decoder import decode as asn1decode

from pypassport.doc9303.aes_secure_messaging import AesSecureMessaging
from pypassport.iso7816 import APDUCommand
from pypassport.utils import hex_to_int, long_to_bytearray, toHexString
from pypassport.doc9303.mrz import MRZ


# ---------------------------------------------------------------------------
# OID table — maps dotted-string OID → (key_len_bytes, kdf_hash, der_value)
# KDF hash: 'sha1' for AES-128, 'sha256' for AES-192/256 (TR-03110 §4.3.3)
# ---------------------------------------------------------------------------

_PACE_OIDS = {
    "0.4.0.127.0.7.2.2.4.2.2": (16, "sha1",   bytes([0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02])),
    "0.4.0.127.0.7.2.2.4.2.3": (24, "sha256", bytes([0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03])),
    "0.4.0.127.0.7.2.2.4.2.4": (32, "sha256", bytes([0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04])),
}

# Legacy dict retained for callers that import pace_oid directly.
pace_oid = {k: f"id-PACE-ECDH-GM-AES-CBC-CMAC-{v[0] * 8}" for k, v in _PACE_OIDS.items()}

ef_security_object = ["DG14", "CardAccess"]

# Brainpool P-256-r1 coordinate width in bytes.
_COORD_LEN = 32


class PACEException(Exception):
    pass


class PACE:
    """
    PACE implementation for ECDH Generic Mapping with AES session keys.

    Exactly one of ``mrz``, ``can``, or ``password`` should be supplied:

    :param iso7816:  Transport layer.  Must expose ``mseSetAt``,
        ``generalAuthenticate``, and ``transmit``.
    :param mrz:      MRZ object/tuple/string. The password π is derived as
        SHA-1(MRZ_information) per BSI TR-03110.
    :param can:      Card Access Number — the short numeric code printed on
        the document (typically 6 digits). The CAN is used directly as π
        (its ASCII bytes), not hashed.
    :param password: Raw password bytes (escape hatch for unusual cases).
    """

    PWD_MRZ = bytes([0x01])
    PWD_CAN = bytes([0x02])
    PWD_PIN = bytes([0x03])
    PWD_PUK = bytes([0x04])

    def __init__(self, iso7816, mrz=None, can=None, password=None):
        self.__load_brainpool()
        self._iso7816 = iso7816
        self._password = password
        self._password_ref = None
        if can is not None:
            if isinstance(can, str):
                can = can.strip().encode("ascii")
            self._password = bytes(can)
            self._password_ref = self.PWD_CAN
        elif mrz:
            self._password = self.genKseed(mrz)
            self._password_ref = self.PWD_MRZ

    @property
    def password_reference(self) -> bytes:
        """Return the ICAO password reference byte (0x01 MRZ, 0x02 CAN, ...).
        ``None`` if PACE was initialised with a raw password.
        """
        return self._password_ref

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def genKseed(self, mrz) -> bytes:
        """
        Derive the PACE password from an MRZ object (SHA-1 of MRZ_information).

        The returned value is used directly as the password π; KDF_π is then
        applied inside performPACE to produce K_π.
        """
        if isinstance(mrz, str):
            mrz = MRZ(mrz)
        elif not isinstance(mrz, MRZ):
            raise PACEException("Bad parameter, must be an MRZ object (" + str(type(mrz)) + ")")

        kmrz = (
            mrz.docNumber[0] + mrz.docNumber[1]
            + mrz.dateOfBirth[0] + mrz.dateOfBirth[1]
            + mrz.dateOfExpiry[0] + mrz.dateOfExpiry[1]
        )
        logging.debug("MRZ_information composed for PACE key derivation")
        return hashlib.sha1(kmrz.encode()).digest()

    def getSecurityObject(self):
        raise NotImplementedError("getSecurityObject is not yet implemented")

    def getPACEInfo(self, security_object: bytes):
        """
        Parse a SecurityInfos blob and return the first supported PACE OID
        and its domain parameter byte.

        Returns (oid_bytes, domain_bytes) — oid_bytes is the raw DER value
        (no tag/length prefix), domain_bytes is a 1-byte sequence or b"".
        """
        data = security_object
        elements, _ = asn1decode(data)

        for seq in elements:
            try:
                oid_str = str(seq[0])
                if oid_str in _PACE_OIDS:
                    logging.debug("PACE OID found: %s", oid_str)
                    _, _, oid_der = _PACE_OIDS[oid_str]
                    domain = bytes([int(seq[2])]) if len(seq) > 2 else b""
                    return oid_der, domain
            except Exception:
                continue
        return None, b""

    def performPACE(self, algorithm_oid: bytes, pw_ref: bytes, domain_params: bytes = b"", chat: bytes = b"") -> None:
        """
        Execute the full PACE-ECDH-GM flow (GA1 – GA4) and install AES Secure
        Messaging on ``self._iso7816.ciphering``.

        :param algorithm_oid: Raw DER value of the PACE OID (no 0x06 tag).
        :param pw_ref:        Password reference byte(s), e.g. b"\\x01" for MRZ.
        :param domain_params: Optional domain-parameter-ID byte (1 byte or b"").
        :param chat:          Optional CHAT object (may be empty).
        :raise PACEException: On any protocol or crypto failure.
        """
        logging.debug("Starting PACE")

        # Resolve cipher parameters from the OID bytes.
        key_len, hash_algo, oid_der = self._params_from_oid(algorithm_oid)

        # ── MSE:Set AT ──────────────────────────────────────────────────
        self._iso7816.mseSetAt(algorithm_oid, pw_ref, domain_params, chat)

        # ── GA1: obtain and decrypt the nonce ───────────────────────────
        ga1_raw = bytes(self._iso7816.generalAuthenticate())
        encrypted_nonce = self._parse_ga_response(ga1_raw, 0x80)

        k_pi = self.kdf(self._password, 3, key_len, hash_algo)
        s = self._decrypt_nonce(k_pi, bytes(encrypted_nonce))
        logging.debug("PACE nonce decrypted (s redacted)")

        # ── GA2: first ephemeral ECDH key exchange ──────────────────────
        pcd_pk_x1 = self._get_x1()
        ga2_raw = self._send_ga(0x81, pcd_pk_x1, cla=0x10)
        picc_pk_y1 = self._parse_ga_response(ga2_raw, 0x82)

        # ── Generic Mapping: G' = s·G + H (H = x1·Y1) ──────────────────
        pcd_pk_x2 = self._get_x2(bytes(picc_pk_y1), s)

        # ── GA3: second ephemeral ECDH key exchange over mapped group ───
        ga3_raw = self._send_ga(0x83, pcd_pk_x2, cla=0x10)
        picc_pk_y2 = self._parse_ga_response(ga3_raw, 0x84)

        # ── Derive session keys ─────────────────────────────────────────
        shared_secret = self._get_shared_secret(bytes(picc_pk_y2))
        k_enc = self.kdf(bytes(shared_secret), 1, key_len, hash_algo)
        k_mac = self.kdf(bytes(shared_secret), 2, key_len, hash_algo)
        logging.debug("PACE session keys derived (redacted)")

        # ── GA4: authenticate ───────────────────────────────────────────
        t_pcd = self._calc_auth_token(k_mac, list(oid_der), bytearray(picc_pk_y2))
        ga4_raw = self._send_ga(0x85, t_pcd, cla=0x00)
        t_picc_received = self._parse_ga_response(ga4_raw, 0x86)

        t_picc_expected = self._calc_auth_token(k_mac, list(oid_der), bytearray(pcd_pk_x2))
        if bytes(t_picc_received) != bytes(t_picc_expected):
            raise PACEException("PACE authentication failed: T_PICC mismatch")

        # ── Install AES Secure Messaging ────────────────────────────────
        ssc = b"\x00" * 16
        self._iso7816.ciphering = AesSecureMessaging(k_enc, k_mac, ssc)
        logging.debug("PACE completed — AES Secure Messaging enabled")

    # ------------------------------------------------------------------
    # KDF / crypto helpers (kept public for backward compatibility)
    # ------------------------------------------------------------------

    def kdf(self, password: bytes, c: int, key_len: int = 16, hash_algo: str = "sha1") -> bytes:
        """
        BSI TR-03110 §4.3.3 KDF.

        :param password:  Key material (Kseed or shared-secret x-coordinate).
        :param c:         Counter byte (1=K_enc, 2=K_mac, 3=K_π).
        :param key_len:   Desired output length in bytes (16, 24, or 32).
        :param hash_algo: Hash to use: ``'sha1'`` (AES-128) or ``'sha256'``
                          (AES-192/256).
        """
        data = bytes(password) + bytes([0, 0, 0, c])
        if hash_algo == "sha256":
            digest = hashlib.sha256(data).digest()
        else:
            digest = hashlib.sha1(data).digest()
        return digest[:key_len]

    def getCMAC(self, key: bytes, data: bytes) -> bytes:
        cmac = CMAC.new(bytes(key), ciphermod=AES)
        cmac.update(bytes(data))
        return bytearray(cmac.digest())

    def getMAC(self, key: bytes, ssc: bytes, data: bytes) -> bytes:
        n = ssc + data
        padded = self.addPadding(n)
        cmac = CMAC.new(bytes(key), ciphermod=AES)
        cmac.update(padded)
        return bytearray(cmac.digest())

    def decryptBlock(self, key: bytes, ciphertext: bytes) -> bytearray:
        return bytearray(AES.new(bytes(key), AES.MODE_ECB).decrypt(bytes(ciphertext)))

    def encryptBlock(self, key: bytes, plaintext: bytes) -> bytearray:
        return bytearray(AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(plaintext)))

    def decrypt(self, key: bytes, ssc: bytes, ciphertext: bytes) -> bytearray:
        iv = self.encryptBlock(key, ssc)
        aes = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        return bytearray(self.addPadding(aes.decrypt(bytes(ciphertext))))

    def encrypt(self, key: bytes, ssc: bytes, plaintext: bytes) -> bytearray:
        iv = self.encryptBlock(key, ssc)
        aes = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        return bytearray(aes.encrypt(self.addPadding(bytes(plaintext))))

    def addPadding(self, data) -> bytes:
        return Padding.pad(bytes(data), AES.block_size, style="iso7816")

    # ------------------------------------------------------------------
    # Internal PACE steps
    # ------------------------------------------------------------------

    def _params_from_oid(self, oid_bytes: bytes):
        """
        Return (key_len, hash_algo, oid_der) for the given OID bytes.

        Accepts the DER value form (no tag/length) or performs a last-byte
        lookup as a fallback.
        """
        oid_bytes = bytes(oid_bytes)
        for oid_str, (key_len, hash_algo, oid_der) in _PACE_OIDS.items():
            if oid_bytes == oid_der:
                return key_len, hash_algo, oid_der
        # Fallback: check the last byte for the AES variant indicator.
        last = oid_bytes[-1] if oid_bytes else 0
        for oid_str, (key_len, hash_algo, oid_der) in _PACE_OIDS.items():
            if oid_der[-1] == last:
                return key_len, hash_algo, oid_der
        raise PACEException(f"Unsupported PACE OID (bytes: {toHexString(list(oid_bytes))})")

    def _decrypt_nonce(self, k_pi: bytes, ciphertext: bytes) -> bytes:
        """AES-CBC decrypt the chip's encrypted nonce with IV=0."""
        iv = b"\x00" * AES.block_size
        return AES.new(k_pi, AES.MODE_CBC, iv).decrypt(ciphertext)

    def _get_x1(self) -> bytearray:
        """Generate the first PCD ephemeral private key and return the public key."""
        self.__pcd_sk_x1 = hex_to_int(bytearray(get_random_bytes(_COORD_LEN)))
        pk = self.pointG * self.__pcd_sk_x1
        return self._point_to_bytes(pk)

    def _get_x2(self, picc_pk_y1: bytes, s: bytes) -> bytearray:
        """
        Generic Mapping and second ephemeral key generation.

        G' = s·G + H  where  H = x1·Y1
        Returns X2 = x2·G'  (uncompressed, 04 || x || y).
        """
        y1 = self._bytes_to_point(picc_pk_y1)
        H = y1 * self.__pcd_sk_x1
        g_prime = (self.pointG * hex_to_int(s)) + H
        self.__g_prime = g_prime

        self.__pcd_sk_x2 = hex_to_int(bytearray(get_random_bytes(_COORD_LEN)))
        pk = g_prime * self.__pcd_sk_x2
        return self._point_to_bytes(pk)

    def _get_shared_secret(self, picc_pk_y2: bytes) -> bytearray:
        """Compute K = x2·Y2; return the x-coordinate as bytes."""
        y2 = self._bytes_to_point(picc_pk_y2)
        K = y2 * self.__pcd_sk_x2
        return _pad_coord(long_to_bytearray(K.x()))

    def _calc_auth_token(self, k_mac: bytes, algorithm_oid: list, pk: bytearray) -> bytearray:
        """
        Compute the 8-byte PACE authentication token T = CMAC(K_mac, input)[:8].

        Input ::= 7F49 L { 06 L_oid OID  86 L_pk PK }
        """
        oid_tlv = [0x06, len(algorithm_oid)] + algorithm_oid
        inner = oid_tlv + [0x86, len(pk)] + list(pk)
        mac_input = [0x7F, 0x49, len(inner)] + inner
        return bytearray(self.getCMAC(k_mac, bytearray(mac_input)))[:8]

    # ------------------------------------------------------------------
    # APDU transport helpers
    # ------------------------------------------------------------------

    def _send_ga(self, inner_tag: int, inner_data: bytes, *, cla: int = 0x10) -> bytes:
        """Build and send a General Authenticate APDU; return the raw response data."""
        inner = bytes([inner_tag, len(inner_data)]) + bytes(inner_data)
        outer = bytes([0x7C, len(inner)]) + inner
        toSend = APDUCommand(cla, 0x86, 0x00, 0x00, data=outer, le=0x00)
        return bytes(self._iso7816.transmit(toSend, f"PACE GA (tag={inner_tag:#04x})"))

    def _parse_ga_response(self, data: bytes, expected_inner_tag: int) -> bytes:
        """Parse  7C L <inner_tag> L <value>  from a GA response data field."""
        data = bytes(data)
        if not data or data[0] != 0x7C:
            raise PACEException(f"GA response: expected 0x7C, got {data[0]:#04x}")
        outer_len, consumed = _asn1_len(data[1:])
        offset = 1 + consumed
        inner = data[offset: offset + outer_len]

        if not inner or inner[0] != expected_inner_tag:
            got = inner[0] if inner else 0
            raise PACEException(
                f"GA response inner tag: expected {expected_inner_tag:#04x}, got {got:#04x}"
            )
        inner_len, consumed2 = _asn1_len(inner[1:])
        return inner[1 + consumed2: 1 + consumed2 + inner_len]

    # ------------------------------------------------------------------
    # Curve helpers
    # ------------------------------------------------------------------

    def _bytes_to_point(self, data: bytes) -> Point:
        """Parse an uncompressed EC point (04 || x || y) into a Point."""
        if data[0] != 0x04:
            raise PACEException(f"Unsupported EC point format: {data[0]:#04x}")
        x = data[1: 1 + _COORD_LEN]
        y = data[1 + _COORD_LEN: 1 + 2 * _COORD_LEN]
        return Point(self.curve_brainpoolp256r1, hex_to_int(x), hex_to_int(y), self._q)

    def _point_to_bytes(self, point: Point) -> bytearray:
        """Encode a Point as an uncompressed EC point (04 || x || y)."""
        x = _pad_coord(long_to_bytearray(point.x()))
        y = _pad_coord(long_to_bytearray(point.y()))
        return bytearray([0x04]) + x + y

    def __load_brainpool(self):
        _a  = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
        _b  = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
        _p  = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
        _Gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
        _Gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
        self._q = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7

        self.curve_brainpoolp256r1 = CurveFp(_p, _a, _b)
        self.pointG = Point(self.curve_brainpoolp256r1, _Gx, _Gy, self._q)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _pad_coord(coord: bytearray) -> bytearray:
    """Left-pad a coordinate bytearray to exactly _COORD_LEN bytes."""
    b = bytes(coord)
    if len(b) < _COORD_LEN:
        b = b"\x00" * (_COORD_LEN - len(b)) + b
    return bytearray(b[:_COORD_LEN])


def _asn1_len(data: bytes):
    """Return (length, bytes_consumed) for a BER/DER length field."""
    data = bytes(data)
    if data[0] <= 0x7F:
        return data[0], 1
    if data[0] == 0x81:
        return data[1], 2
    if data[0] == 0x82:
        return (data[1] << 8) | data[2], 3
    raise PACEException("ASN.1 length field too long or malformed")
