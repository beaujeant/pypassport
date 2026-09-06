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

from __future__ import annotations

import hashlib
import logging

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from ecdsa.ellipticcurve import CurveFp, Point
from pyasn1.codec.der.decoder import decode as asn1decode

from pypassport.doc9303.aes_secure_messaging import AesSecureMessaging
from pypassport.doc9303.secure_messaging import SecureMessaging
from pypassport.doc9303.domain_parameters import DHParameters, resolve as resolve_domain_parameters
from pypassport.iso9797 import mac as retail_mac, pad as des_pad
from pypassport.asn1 import to_asn1_length
from pypassport.iso7816 import APDUCommand
from pypassport.utils import hex_to_int, long_to_bytearray, to_hex_string
from pypassport.doc9303.mrz import MRZ


# ---------------------------------------------------------------------------
# OID table — maps dotted-string OID → (key_len_bytes, kdf_hash, der_value)
# KDF hash: 'sha1' for AES-128, 'sha256' for AES-192/256 (TR-03110 §4.3.3)
# ---------------------------------------------------------------------------

def _oid_value(oid):
    values = [int(x) for x in oid.split(".")]
    out = bytearray([values[0] * 40 + values[1]])
    for value in values[2:]:
        encoded = [value & 0x7F]
        value >>= 7
        while value:
            encoded.append((value & 0x7F) | 0x80)
            value >>= 7
        out.extend(reversed(encoded))
    return bytes(out)


_PACE_PROFILES = {}
for _ka, _ka_code in (("DH", 1), ("ECDH", 2)):
    for _mapping, _mapping_code in (("GM", _ka_code), ("IM", _ka_code + 2)):
        for _cipher, _suite, _bits, _length, _hash in (
            ("3DES", 1, 112, 16, "sha1"), ("AES", 2, 128, 16, "sha1"),
            ("AES", 3, 192, 24, "sha256"), ("AES", 4, 256, 32, "sha256"),
        ):
            _oid = f"0.4.0.127.0.7.2.2.4.{_mapping_code}.{_suite}"
            _PACE_PROFILES[_oid] = (_ka, _mapping, _cipher, _bits, _length, _hash, _oid_value(_oid))
for _suite, _bits, _length, _hash in ((2, 128, 16, "sha1"), (3, 192, 24, "sha256"), (4, 256, 32, "sha256")):
    _oid = f"0.4.0.127.0.7.2.2.4.6.{_suite}"
    _PACE_PROFILES[_oid] = ("ECDH", "CAM", "AES", _bits, _length, _hash, _oid_value(_oid))
_PACE_OIDS = {oid: (profile[4], profile[5], profile[6]) for oid, profile in _PACE_PROFILES.items()}

# Brainpool P-256-r1 coordinate width in bytes.
_COORD_LEN = 32


class PACEException(Exception):
    pass


class PACE:
    """
    PACE implementation for ECDH Generic Mapping with AES session keys.

    Exactly one of ``mrz``, ``can``, or ``password`` should be supplied:

    :param iso7816:  Transport layer.  Must expose ``mse_set_at``,
        ``general_authenticate``, and ``transmit``.
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

    def __init__(self, iso7816, mrz=None, can=None, pin=None, puk=None, password: bytes | None = None):
        self.__load_brainpool()
        self._iso7816 = iso7816
        self._password: bytes | None = password
        self._password_ref: bytes | None = None
        supplied = [(self.PWD_CAN, can), (self.PWD_PIN, pin), (self.PWD_PUK, puk)]
        selected = next(((ref, value) for ref, value in supplied if value is not None), None)
        if sum(value is not None for _, value in supplied) + (password is not None) > 1:
            raise PACEException("Supply exactly one CAN, PIN, PUK, or raw password")
        if selected:
            self._password_ref, value = selected
            if isinstance(value, str):
                value = value.strip().encode("ascii")
            self._password = bytes(value)
        elif mrz:
            self._password = self.gen_kseed(mrz)
            self._password_ref = self.PWD_MRZ

    @property
    def password_reference(self) -> bytes | None:
        """Return the ICAO password reference byte (0x01 MRZ, 0x02 CAN, ...).
        ``None`` if PACE was initialised with a raw password.
        """
        return self._password_ref

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def gen_kseed(self, mrz) -> bytes:
        """
        Derive the PACE password from an MRZ object (SHA-1 of MRZ_information).

        The returned value is used directly as the password π; KDF_π is then
        applied inside perform_pace to produce K_π.
        """
        if isinstance(mrz, str):
            mrz = MRZ(mrz)
        elif not isinstance(mrz, MRZ):
            raise PACEException("Bad parameter, must be an MRZ object (" + str(type(mrz)) + ")")

        kmrz = (
            mrz.doc_number[0]
            + mrz.doc_number[1]
            + mrz.date_of_birth[0]
            + mrz.date_of_birth[1]
            + mrz.date_of_expiry[0]
            + mrz.date_of_expiry[1]
        )
        logging.debug("MRZ_information composed for PACE key derivation")
        return hashlib.sha1(kmrz.encode()).digest()

    def get_pace_info(self, security_object: bytes):
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

    def perform_pace(self, algorithm_oid: bytes, pw_ref: bytes, domain_params: bytes = b"", chat: bytes = b"",
                     explicit_domain_parameters=None, parameter_id=None) -> None:
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
        profile = next(profile for profile in _PACE_PROFILES.values() if profile[6] == bytes(algorithm_oid))
        self._key_agreement, self._mapping, self._cipher = profile[:3]
        self._key_len = key_len
        parameter_id = parameter_id if parameter_id is not None else (int.from_bytes(domain_params, "big") if domain_params else None)
        self._configure_domain(parameter_id, explicit_domain_parameters)

        # ── MSE:Set AT ──────────────────────────────────────────────────
        self._iso7816.mse_set_at(algorithm_oid, pw_ref, domain_params, chat)

        # ── GA1: obtain and decrypt the nonce ───────────────────────────
        ga1_raw = bytes(self._iso7816.general_authenticate())
        encrypted_nonce = self._parse_ga_response(ga1_raw, 0x80)

        if self._password is None:
            raise PACEException("PACE requires an MRZ, CAN, or raw password")
        k_pi = self.kdf(self._password, 3, key_len, hash_algo)
        s = self._decrypt_nonce(k_pi, bytes(encrypted_nonce))
        logging.debug("PACE nonce decrypted (s redacted)")

        # ── GA2: first ephemeral ECDH key exchange ──────────────────────
        if self._mapping in ("GM", "CAM"):
            pcd_pk_x1 = self._get_x1()
            ga2_raw = self._send_ga(0x81, pcd_pk_x1, cla=0x10)
            picc_pk_y1 = self._parse_ga_response(ga2_raw, 0x82)
            self._cam_mapping_public_key = bytes(picc_pk_y1) if self._mapping == "CAM" else None
            pcd_pk_x2 = self._get_x2(bytes(picc_pk_y1), s)
        else:
            mapping_nonce = get_random_bytes(key_len)
            ga2_raw = self._send_ga(0x81, mapping_nonce, cla=0x10)
            self._parse_empty_ga(ga2_raw)
            pcd_pk_x2 = self._get_im_x2(s, mapping_nonce)

        # ── GA3: second ephemeral ECDH key exchange over mapped group ───
        ga3_raw = self._send_ga(0x83, pcd_pk_x2, cla=0x10)
        picc_pk_y2 = self._parse_ga_response(ga3_raw, 0x84)

        # ── Derive session keys ─────────────────────────────────────────
        shared_secret = self._get_shared_secret(bytes(picc_pk_y2))
        k_enc = self.kdf(bytes(shared_secret), 1, key_len, hash_algo)
        k_mac = self.kdf(bytes(shared_secret), 2, key_len, hash_algo)
        if self._cipher == "3DES":
            k_enc, k_mac = _odd_parity(k_enc), _odd_parity(k_mac)
        logging.debug("PACE session keys derived (redacted)")

        # ── GA4: authenticate ───────────────────────────────────────────
        t_pcd = self._calc_auth_token(k_mac, list(oid_der), bytearray(picc_pk_y2))
        ga4_raw = self._send_ga(0x85, t_pcd, cla=0x00)
        ga4_elements = self._parse_ga_elements(ga4_raw)
        if 0x86 not in ga4_elements:
            raise PACEException("PACE authentication response has no token")
        t_picc_received = ga4_elements[0x86]
        self._cam_encrypted_data = ga4_elements.get(0x8A)
        if (self._mapping == "CAM") != (self._cam_encrypted_data is not None):
            raise PACEException("Encrypted Chip Authentication Data presence conflicts with the PACE mapping")

        t_picc_expected = self._calc_auth_token(k_mac, list(oid_der), bytearray(pcd_pk_x2))
        if bytes(t_picc_received) != bytes(t_picc_expected):
            raise PACEException("PACE authentication failed: T_PICC mismatch")

        # ── Install AES Secure Messaging ────────────────────────────────
        ssc = b"\x00" * 16
        self._iso7816.ciphering = (AesSecureMessaging(k_enc, k_mac, ssc)
                                   if self._cipher == "AES" else SecureMessaging(k_enc, k_mac, b"\x00" * 8))
        self._pace_k_enc = k_enc
        logging.debug("PACE completed — AES Secure Messaging enabled")

    # ------------------------------------------------------------------
    # KDF / crypto helpers
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

    def get_cmac(self, key: bytes, data: bytes) -> bytes:
        cmac = CMAC.new(bytes(key), ciphermod=AES)
        cmac.update(bytes(data))
        return bytearray(cmac.digest())

    def get_mac(self, key: bytes, ssc: bytes, data: bytes) -> bytes:
        n = ssc + data
        padded = self.add_padding(n)
        cmac = CMAC.new(bytes(key), ciphermod=AES)
        cmac.update(padded)
        return bytearray(cmac.digest())

    def decrypt_block(self, key: bytes, ciphertext: bytes) -> bytearray:
        return bytearray(AES.new(bytes(key), AES.MODE_ECB).decrypt(bytes(ciphertext)))

    def encrypt_block(self, key: bytes, plaintext: bytes) -> bytearray:
        return bytearray(AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(plaintext)))

    def decrypt(self, key: bytes, ssc: bytes, ciphertext: bytes) -> bytearray:
        iv = self.encrypt_block(key, ssc)
        aes = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        return bytearray(self.add_padding(aes.decrypt(bytes(ciphertext))))

    def encrypt(self, key: bytes, ssc: bytes, plaintext: bytes) -> bytearray:
        iv = self.encrypt_block(key, ssc)
        aes = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        return bytearray(aes.encrypt(self.add_padding(bytes(plaintext))))

    def add_padding(self, data) -> bytes:
        return Padding.pad(bytes(data), AES.block_size, style="iso7816")

    # ------------------------------------------------------------------
    # Internal PACE steps
    # ------------------------------------------------------------------

    def _params_from_oid(self, oid_bytes: bytes):
        """
        Return (key_len, hash_algo, oid_der) for the given OID bytes.
        """
        oid_bytes = bytes(oid_bytes)
        for key_len, hash_algo, oid_der in _PACE_OIDS.values():
            if oid_bytes == oid_der:
                return key_len, hash_algo, oid_der
        raise PACEException(f"Unsupported PACE OID (bytes: {to_hex_string(list(oid_bytes))})")

    def _decrypt_nonce(self, k_pi: bytes, ciphertext: bytes) -> bytes:
        """Decrypt the chip's encrypted nonce with the negotiated cipher."""
        if self._cipher == "3DES":
            k_pi = _odd_parity(k_pi)
            if len(ciphertext) % 8:
                raise PACEException("3DES PACE nonce has an invalid length")
            return DES3.new(k_pi, DES3.MODE_CBC, b"\x00" * 8).decrypt(ciphertext)
        if len(ciphertext) % 16:
            raise PACEException("AES PACE nonce has an invalid length")
        return AES.new(k_pi, AES.MODE_CBC, b"\x00" * 16).decrypt(ciphertext)

    def _get_x1(self) -> bytearray:
        """Generate the first PCD ephemeral private key and return the public key."""
        if self._key_agreement == "DH":
            self.__pcd_sk_x1 = self._random_scalar(self._dh.q or self._dh.p - 1)
            return bytearray(pow(self._dh.g, self.__pcd_sk_x1, self._dh.p).to_bytes(self._dh.width, "big"))
        self.__pcd_sk_x1 = self._random_scalar(self._q)
        return self._point_to_bytes(self.pointG * self.__pcd_sk_x1)

    def _get_x2(self, picc_pk_y1: bytes, s: bytes) -> bytearray:
        """
        Generic Mapping and second ephemeral key generation.

        G' = s·G + H  where  H = x1·Y1
        Returns X2 = x2·G'  (uncompressed, 04 || x || y).
        """
        if self._key_agreement == "DH":
            y1 = self._parse_dh_public(picc_pk_y1)
            h = pow(y1, self.__pcd_sk_x1, self._dh.p)
            self.__g_prime = pow(self._dh.g, int.from_bytes(s, "big"), self._dh.p) * h % self._dh.p
            if self.__g_prime in (0, 1):
                raise PACEException("PACE produced a degenerate mapped DH generator")
            self.__pcd_sk_x2 = self._random_scalar(self._dh.q or self._dh.p - 1)
            return bytearray(pow(self.__g_prime, self.__pcd_sk_x2, self._dh.p).to_bytes(self._dh.width, "big"))
        y1 = self._bytes_to_point(picc_pk_y1)
        H = y1 * self.__pcd_sk_x1
        g_prime = (self.pointG * hex_to_int(s)) + H
        self.__g_prime = g_prime

        self.__pcd_sk_x2 = self._random_scalar(self._q)
        pk = g_prime * self.__pcd_sk_x2
        return self._point_to_bytes(pk)

    def _get_shared_secret(self, picc_pk_y2: bytes) -> bytearray:
        """Compute K = x2·Y2; return the x-coordinate as bytes."""
        if self._key_agreement == "DH":
            y2 = self._parse_dh_public(picc_pk_y2)
            return bytearray(pow(y2, self.__pcd_sk_x2, self._dh.p).to_bytes(self._dh.width, "big"))
        y2 = self._bytes_to_point(picc_pk_y2)
        K = y2 * self.__pcd_sk_x2
        return self._pad_coordinate(long_to_bytearray(K.x()))

    def _calc_auth_token(self, k_mac: bytes, algorithm_oid: list, pk: bytearray) -> bytearray:
        """
        Compute the 8-byte PACE authentication token T = CMAC(K_mac, input)[:8].

        Input ::= 7F49 L { 06 L_oid OID  86 L_pk PK }
        """
        oid_tlv = [0x06, len(algorithm_oid)] + algorithm_oid
        public_tag = 0x84 if getattr(self, "_key_agreement", "ECDH") == "DH" else 0x86
        inner = bytes(oid_tlv) + bytes([public_tag]) + to_asn1_length(len(pk)) + bytes(pk)
        mac_input = bytes([0x7F, 0x49]) + to_asn1_length(len(inner)) + inner
        if getattr(self, "_cipher", "AES") == "3DES":
            return bytearray(retail_mac(k_mac, des_pad(mac_input)))[:8]
        return bytearray(self.get_cmac(k_mac, mac_input))[:8]

    # ------------------------------------------------------------------
    # APDU transport helpers
    # ------------------------------------------------------------------

    def _send_ga(self, inner_tag: int, inner_data: bytes, *, cla: int = 0x10) -> bytes:
        """Build and send a General Authenticate APDU; return the raw response data."""
        inner = bytes([inner_tag]) + to_asn1_length(len(inner_data)) + bytes(inner_data)
        outer = bytes([0x7C]) + to_asn1_length(len(inner)) + inner
        toSend = APDUCommand(cla, 0x86, 0x00, 0x00, data=outer, le=256)
        return bytes(self._iso7816.transmit(toSend, f"PACE GA (tag={inner_tag:#04x})"))

    def _parse_ga_response(self, data: bytes, expected_inner_tag: int) -> bytes:
        """Parse  7C L <inner_tag> L <value>  from a GA response data field."""
        data = bytes(data)
        if not data or data[0] != 0x7C:
            raise PACEException(f"GA response: expected 0x7C, got {data[0]:#04x}")
        outer_len, consumed = _asn1_len(data[1:])
        offset = 1 + consumed
        if offset + outer_len != len(data):
            raise PACEException("GA response outer length mismatch or trailing data")
        inner = data[offset : offset + outer_len]

        if not inner or inner[0] != expected_inner_tag:
            got = inner[0] if inner else 0
            raise PACEException(f"GA response inner tag: expected {expected_inner_tag:#04x}, got {got:#04x}")
        inner_len, consumed2 = _asn1_len(inner[1:])
        if 1 + consumed2 + inner_len != len(inner):
            raise PACEException("GA response inner length mismatch or trailing data")
        return inner[1 + consumed2 : 1 + consumed2 + inner_len]

    def _parse_ga_elements(self, data):
        data = bytes(data)
        if not data or data[0] != 0x7C:
            raise PACEException("GA response is not a Dynamic Authentication template")
        length, used = _asn1_len(data[1:])
        if 1 + used + length != len(data):
            raise PACEException("GA response length mismatch")
        elements, offset = {}, 1 + used
        while offset < len(data):
            tag = data[offset]
            value_length, length_used = _asn1_len(data[offset + 1:])
            start, end = offset + 1 + length_used, offset + 1 + length_used + value_length
            if end > len(data) or tag in elements:
                raise PACEException("Malformed/duplicate GA response data object")
            elements[tag] = data[start:end]
            offset = end
        return elements

    def _parse_empty_ga(self, data):
        elements = self._parse_ga_elements(data)
        if elements != {0x82: b""}:
            raise PACEException("PACE-IM mapping response must contain empty DO82")

    def verify_cam(self, card_security):
        """Validate encrypted CAM data against signed EF.CardSecurity."""
        if self._mapping != "CAM" or not self._cam_encrypted_data or not self._cam_mapping_public_key:
            raise PACEException("No pending PACE-CAM authentication data")
        if not card_security.get("signature_valid"):
            raise PACEException("EF.CardSecurity CMS signature is invalid")
        from pypassport.doc9303.chip_authentication import ChipAuthentication

        key_id = getattr(self, "_parameter_id", None)
        keys = [info for info in card_security.get("security_infos", [])
                if str(info.get("protocol_oid", "")).startswith("0.4.0.127.0.7.2.2.1.2")
                and (key_id is None or info.get("key_id") == key_id)]
        if len(keys) != 1:
            raise PACEException("EF.CardSecurity has no unambiguous CAM public key")
        static, domain, _width = ChipAuthentication(self._iso7816)._public_key(keys[0], "ECDH")
        if len(self._cam_encrypted_data) % AES.block_size:
            raise PACEException("Encrypted PACE-CAM data is not an AES block sequence")
        iv = AES.new(self._pace_k_enc, AES.MODE_ECB).encrypt(b"\xFF" * 16)
        padded = AES.new(self._pace_k_enc, AES.MODE_CBC, iv).decrypt(self._cam_encrypted_data)
        try:
            ca_data = Padding.unpad(padded, AES.block_size, style="iso7816")
        except ValueError as exc:
            raise PACEException("PACE-CAM data has invalid padding") from exc
        if len(ca_data) != (self._q.bit_length() + 7) // 8 or domain.curve != self.curve_brainpoolp256r1:
            raise PACEException("PACE-CAM data/domain has an invalid length or parameters")
        scalar = int.from_bytes(ca_data, "big")
        if not 1 <= scalar < self._q:
            raise PACEException("PACE-CAM scalar is outside the group order")
        expected = self._bytes_to_point(self._cam_mapping_public_key)
        if static * scalar != expected:
            raise PACEException("PACE-CAM failed to bind mapping key to EF.CardSecurity")
        return {"key_id": keys[0].get("key_id"), "card_security_signature_valid": True,
                "card_security_signer_trusted": False, "passive_authentication": "pending",
                "chip_authentication_verified": True}

    def _get_im_x2(self, s, mapping_nonce):
        """Integrated Mapping R(s,t), followed by the ephemeral public key."""
        output_bits = 128 if self._cipher == "3DES" or self._key_len == 16 else 256
        c0 = bytes.fromhex("a668892a7c41e3ca739f40b057d85904") if output_bits == 128 else bytes.fromhex(
            "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676")
        c1 = bytes.fromhex("a4e136ac725f738b01c1f60217c188ad") if output_bits == 128 else bytes.fromhex(
            "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517")
        if len(s) * 8 != output_bits or len(mapping_nonce) != self._key_len:
            raise PACEException("PACE-IM nonce lengths conflict with the selected cipher")

        def encrypt(key, value):
            if self._cipher == "AES":
                return AES.new(key, AES.MODE_CBC, b"\x00" * 16).encrypt(value)
            return DES3.new(_odd_parity(key), DES3.MODE_CBC, b"\x00" * 8).encrypt(value)

        key = encrypt(mapping_nonce, s)[:self._key_len]
        modulus_bits = self._dh.p.bit_length() if self._key_agreement == "DH" else self.curve_brainpoolp256r1.p().bit_length()
        blocks = (modulus_bits + 64 + output_bits - 1) // output_bits
        mapped = bytearray()
        for _ in range(blocks):
            mapped.extend(encrypt(key, c1))
            key = encrypt(key, c0)[:self._key_len]
        u = int.from_bytes(mapped, "big")
        if self._key_agreement == "DH":
            if self._dh.q is None:
                raise PACEException("DH Integrated Mapping requires the subgroup order q")
            self.__g_prime = pow(u, (self._dh.p - 1) // self._dh.q, self._dh.p)
            if self.__g_prime in (0, 1):
                raise PACEException("PACE-IM produced a degenerate DH generator")
            self.__pcd_sk_x2 = self._random_scalar(self._dh.q)
            return bytearray(pow(self.__g_prime, self.__pcd_sk_x2, self._dh.p).to_bytes(self._dh.width, "big"))
        p = self.curve_brainpoolp256r1.p()
        a = self.curve_brainpoolp256r1.a()
        b = self.curve_brainpoolp256r1.b()
        if p <= 3 or p % 4 != 3 or u % p == 0:
            raise PACEException("Negotiated curve is unsuitable for PACE Integrated Mapping")
        u %= p
        alpha = -u * u % p
        alpha_sum = (alpha + alpha * alpha) % p
        x2 = -b * pow(a, -1, p) * (1 + pow(alpha_sum, -1, p)) % p
        x3 = alpha * x2 % p
        h2 = (pow(x2, 3, p) + a * x2 + b) % p
        mapped_u = pow(u, 3, p) * h2 % p
        root = pow(h2, p - 1 - (p + 1) // 4, p)
        if root * root * h2 % p == 1:
            x, y = x2, root * h2 % p
        else:
            x, y = x3, root * mapped_u % p
        if not self.curve_brainpoolp256r1.contains_point(x, y):
            raise PACEException("PACE-IM mapping did not produce a curve point")
        self.__g_prime = Point(self.curve_brainpoolp256r1, x, y, self._q) * (self.curve_brainpoolp256r1.cofactor() or 1)
        self.__pcd_sk_x2 = self._random_scalar(self._q)
        return self._point_to_bytes(self.__g_prime * self.__pcd_sk_x2)

    # ------------------------------------------------------------------
    # Curve helpers
    # ------------------------------------------------------------------

    def _bytes_to_point(self, data: bytes) -> Point:
        """Parse an uncompressed EC point (04 || x || y) into a Point."""
        if len(data) != 1 + 2 * self._coord_len or data[0] != 0x04:
            got = f"{data[0]:#04x}" if data else "empty"
            raise PACEException(f"Unsupported EC point format: {got}")
        x = int.from_bytes(data[1 : 1 + self._coord_len], "big")
        y = int.from_bytes(data[1 + self._coord_len :], "big")
        if not self.curve_brainpoolp256r1.contains_point(x, y):
            raise PACEException("PACE public key is not on the negotiated curve")
        point = Point(self.curve_brainpoolp256r1, x, y, self._q)
        if point * self._q != self.pointG * 0:
            raise PACEException("PACE public key is not in the prime-order subgroup")
        return point

    def _point_to_bytes(self, point: Point) -> bytearray:
        """Encode a Point as an uncompressed EC point (04 || x || y)."""
        x = self._pad_coordinate(long_to_bytearray(point.x()))
        y = self._pad_coordinate(long_to_bytearray(point.y()))
        return bytearray([0x04]) + x + y

    def __load_brainpool(self):
        _a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
        _b = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
        _p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
        _Gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
        _Gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
        self._q = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7

        self.curve_brainpoolp256r1 = CurveFp(_p, _a, _b)
        self.pointG = Point(self.curve_brainpoolp256r1, _Gx, _Gy, self._q)
        self._coord_len = 32
        self._key_agreement = "ECDH"
        self._mapping = "GM"
        self._cipher = "AES"

    def _configure_domain(self, parameter_id, explicit_der):
        self._parameter_id = parameter_id
        try:
            domain = resolve_domain_parameters(self._key_agreement, parameter_id, explicit_der)
        except Exception as exc:
            raise PACEException(str(exc)) from exc
        if isinstance(domain, DHParameters):
            self._dh = domain
        else:
            self.curve_brainpoolp256r1 = domain.curve
            self.pointG = Point(domain.curve, domain.generator.x(), domain.generator.y(), domain.order)
            self._q = domain.order
            self._coord_len = (domain.curve.p().bit_length() + 7) // 8

    def _random_scalar(self, order):
        width = (order.bit_length() + 7) // 8
        while True:
            scalar = int.from_bytes(get_random_bytes(width), "big") % order
            if scalar:
                return scalar

    def _parse_dh_public(self, encoded):
        value = int.from_bytes(encoded, "big")
        if len(encoded) != self._dh.width or not 2 <= value <= self._dh.p - 2:
            raise PACEException("Invalid DH public key")
        if self._dh.q and pow(value, self._dh.q, self._dh.p) != 1:
            raise PACEException("DH public key is outside the negotiated subgroup")
        return value

    def _pad_coordinate(self, coord):
        return bytearray(bytes(coord).rjust(self._coord_len, b"\x00")[-self._coord_len:])


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


def _odd_parity(key):
    return bytes((byte & 0xFE) | (not ((byte & 0xFE).bit_count() & 1)) for byte in key)
