"""Two-party transcript tests for every PACE cipher/KDF branch.

The terminal implementation is exercised normally.  The simulated PICC uses
independent modular/point arithmetic and validates the terminal's GA token.
"""

import hashlib

import pytest
from Crypto.Cipher import AES, DES3
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad
from ecdsa.ellipticcurve import Point
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.asn1 import to_asn1_length
from pypassport.doc9303.domain_parameters import DHParameters, resolve
from pypassport.doc9303.pace import PACE, _odd_parity, _oid_value
from pypassport.doc9303.secure_messaging import SecureMessaging
from pypassport.iso9797 import mac as retail_mac, pad as des_pad
from pypassport.utils import parse_tlv


def _wrap(tag, value):
    inner = bytes([tag]) + to_asn1_length(len(value)) + value
    return b"\x7c" + to_asn1_length(len(inner)) + inner


def _token(key, oid, public, agreement, cipher):
    public_tag = 0x84 if agreement == "DH" else 0x86
    inner = b"\x06" + to_asn1_length(len(oid)) + oid
    inner += bytes([public_tag]) + to_asn1_length(len(public)) + public
    encoded = b"\x7f\x49" + to_asn1_length(len(inner)) + inner
    if cipher == "3DES":
        return retail_mac(key, des_pad(encoded))[:8]
    cmac = CMAC.new(key, ciphermod=AES)
    cmac.update(encoded)
    return cmac.digest()[:8]


class _PICC:
    def __init__(self, agreement, mapping, suite, parameter_id):
        self.agreement = agreement
        self.mapping = mapping
        self.suite = suite
        self.cipher = "3DES" if suite == 1 else "AES"
        self.key_len = {1: 16, 2: 16, 3: 24, 4: 32}[suite]
        self.hash_fn = hashlib.sha1 if suite in (1, 2) else hashlib.sha256
        self.domain = resolve(agreement, parameter_id)
        self.password = bytes.fromhex("239AB9CB282DAF66231DC5A452295551")
        self.nonce = bytes.fromhex("0102030405060708090A0B0C0D0E0F10") if suite < 3 else bytes(range(1, 33))
        self.y1, self.y2 = 17, 23
        mapping_code = {
            ("DH", "GM"): 1,
            ("ECDH", "GM"): 2,
            ("DH", "IM"): 3,
            ("ECDH", "IM"): 4,
            ("ECDH", "CAM"): 6,
        }[(agreement, mapping)]
        self.oid = _oid_value(f"0.4.0.127.0.7.2.2.4.{mapping_code}.{suite}")
        self.ciphering = None
        self.seen = []
        k_pi = self.hash_fn(self.password + b"\0\0\0\3").digest()[:self.key_len]
        if self.cipher == "3DES":
            self.encrypted_nonce = DES3.new(_odd_parity(k_pi), DES3.MODE_CBC, bytes(8)).encrypt(self.nonce)
        else:
            self.encrypted_nonce = AES.new(k_pi, AES.MODE_CBC, bytes(16)).encrypt(self.nonce)

    def mse_set_at(self, oid, _password_ref, domain, _chat):
        assert oid == self.oid
        assert int.from_bytes(domain, "big") == (0 if self.agreement == "DH" else 13)

    def general_authenticate(self):
        return _wrap(0x80, self.encrypted_nonce)

    def transmit(self, command, _message):
        outer_tag, outer, _ = parse_tlv(bytes.fromhex(command.data))
        tag, value, _ = parse_tlv(outer)
        assert outer_tag == "7C"
        self.seen.append(tag)
        if tag == "81":
            if self.mapping == "IM":
                self.mapped = self._integrated_map(self.nonce, value)
                return _wrap(0x82, b"")
            self.x1 = self._public(value)
            if isinstance(self.domain, DHParameters):
                h = pow(self.x1, self.y1, self.domain.p)
                self.mapped = pow(self.domain.g, int.from_bytes(self.nonce, "big"), self.domain.p) * h % self.domain.p
                self.y1_public = pow(self.domain.g, self.y1, self.domain.p)
            else:
                h = self.x1 * self.y1
                self.mapped = self.domain.generator * int.from_bytes(self.nonce, "big") + h
                self.y1_public = self.domain.generator * self.y1
            return _wrap(0x82, self._encoded(self.y1_public))
        if tag == "83":
            self.x2 = self._public(value)
            y2_public = (pow(self.mapped, self.y2, self.domain.p)
                         if isinstance(self.domain, DHParameters) else self.mapped * self.y2)
            self.y2_public = self._encoded(y2_public)
            shared = (pow(self.x2, self.y2, self.domain.p).to_bytes(self.domain.width, "big")
                      if isinstance(self.domain, DHParameters) else (self.x2 * self.y2).x().to_bytes(self.width, "big"))
            self.k_enc = self.hash_fn(shared + b"\0\0\0\1").digest()[:self.key_len]
            self.k_mac = self.hash_fn(shared + b"\0\0\0\2").digest()[:self.key_len]
            if self.cipher == "3DES":
                self.k_enc, self.k_mac = _odd_parity(self.k_enc), _odd_parity(self.k_mac)
            return _wrap(0x84, self.y2_public)
        assert tag == "85"
        assert value == _token(self.k_mac, self.oid, self.y2_public, self.agreement, self.cipher)
        auth = bytes([0x86, 8]) + _token(self.k_mac, self.oid, self._encoded(self.x2), self.agreement, self.cipher)
        if self.mapping == "CAM":
            iv = AES.new(self.k_enc, AES.MODE_ECB).encrypt(b"\xff" * 16)
            clear = pad(self.y1.to_bytes(self.width, "big"), 16, style="iso7816")
            encrypted = AES.new(self.k_enc, AES.MODE_CBC, iv).encrypt(clear)
            auth += b"\x8a" + to_asn1_length(len(encrypted)) + encrypted
        return b"\x7c" + to_asn1_length(len(auth)) + auth

    def _public(self, encoded):
        if isinstance(self.domain, DHParameters):
            return int.from_bytes(encoded, "big")
        self.width = (self.domain.curve.p().bit_length() + 7) // 8
        return Point(
            self.domain.curve,
            int.from_bytes(encoded[1:1 + self.width], "big"),
            int.from_bytes(encoded[1 + self.width:], "big"),
            self.domain.order,
        )

    def _encoded(self, public):
        if isinstance(self.domain, DHParameters):
            return public.to_bytes(self.domain.width, "big")
        width = (self.domain.curve.p().bit_length() + 7) // 8
        return b"\x04" + public.x().to_bytes(width, "big") + public.y().to_bytes(width, "big")

    def _integrated_map(self, nonce, terminal_nonce):
        output_bits = 128 if self.cipher == "3DES" or self.key_len == 16 else 256
        c0 = bytes.fromhex("a668892a7c41e3ca739f40b057d85904") if output_bits == 128 else bytes.fromhex(
            "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676"
        )
        c1 = bytes.fromhex("a4e136ac725f738b01c1f60217c188ad") if output_bits == 128 else bytes.fromhex(
            "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517"
        )

        def encrypt(key, value):
            if self.cipher == "AES":
                return AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(value)
            return DES3.new(_odd_parity(key), DES3.MODE_CBC, bytes(8)).encrypt(value)

        key = encrypt(terminal_nonce, nonce)[:self.key_len]
        modulus_bits = (
            self.domain.p.bit_length()
            if isinstance(self.domain, DHParameters)
            else self.domain.curve.p().bit_length()
        )
        blocks = (modulus_bits + 64 + output_bits - 1) // output_bits
        mapped = bytearray()
        for _ in range(blocks):
            mapped.extend(encrypt(key, c1))
            key = encrypt(key, c0)[:self.key_len]
        u = int.from_bytes(mapped, "big")
        if isinstance(self.domain, DHParameters):
            return pow(u, (self.domain.p - 1) // self.domain.q, self.domain.p)
        p, a, b = self.domain.curve.p(), self.domain.curve.a(), self.domain.curve.b()
        u %= p
        alpha = -u * u % p
        x2 = -b * pow(a, -1, p) * (1 + pow((alpha + alpha * alpha) % p, -1, p)) % p
        x3 = alpha * x2 % p
        h2 = (pow(x2, 3, p) + a * x2 + b) % p
        root = pow(h2, p - 1 - (p + 1) // 4, p)
        if root * root * h2 % p == 1:
            point = Point(self.domain.curve, x2, root * h2 % p, self.domain.order)
        else:
            point = Point(self.domain.curve, x3, root * pow(u, 3, p) * h2 % p, self.domain.order)
        return point * (self.domain.curve.cofactor() or 1)


@pytest.mark.parametrize(
    ("agreement", "mapping", "suite"),
    [(ka, mapping, suite) for ka in ("DH", "ECDH") for mapping in ("GM", "IM") for suite in range(1, 5)],
)
def test_complete_generic_and_integrated_mapping_transcripts(monkeypatch, agreement, mapping, suite):
    picc = _PICC(agreement, mapping, suite, 0 if agreement == "DH" else 13)
    pace = PACE(picc, password=picc.password)
    scalars = iter((11, 13))
    monkeypatch.setattr(pace, "_random_scalar", lambda _order: next(scalars))
    if mapping == "IM":
        monkeypatch.setattr("pypassport.doc9303.pace.get_random_bytes", lambda length: bytes(range(33, 33 + length)))
    pace.perform_pace(picc.oid, b"\x03", bytes([0 if agreement == "DH" else 13]))

    assert picc.seen == ["81", "83", "85"]
    assert pace._pace_k_enc == picc.k_enc
    assert picc.ciphering._ksmac == picc.k_mac
    assert isinstance(picc.ciphering, SecureMessaging) is (suite == 1)


def _ca_spki(domain, public):
    parameters = univ.Sequence()
    parameters.setComponentByPosition(0, univ.ObjectIdentifier("0.4.0.127.0.7.1.2"))
    parameters.setComponentByPosition(1, univ.Integer(13))
    algorithm = univ.Sequence()
    algorithm.setComponentByPosition(0, univ.ObjectIdentifier("0.4.0.127.0.7.2.2.1.2"))
    algorithm.setComponentByPosition(1, parameters)
    width = (domain.curve.p().bit_length() + 7) // 8
    public_bytes = b"\x04" + public.x().to_bytes(width, "big") + public.y().to_bytes(width, "big")
    spki = univ.Sequence()
    spki.setComponentByPosition(0, algorithm)
    spki.setComponentByPosition(1, univ.BitString.fromOctetString(public_bytes))
    return {"protocol_oid": str(algorithm[0]), "key_id": 13, "public_key": {"spki_der_hex": der_encode(spki).hex()}}


@pytest.mark.parametrize("suite", (2, 3, 4))
def test_complete_cam_transcript_produces_verifiable_encrypted_binding(monkeypatch, suite):
    picc = _PICC("ECDH", "CAM", suite, 13)
    picc.width = 32
    pace = PACE(picc, password=picc.password)
    scalars = iter((11, 13))
    monkeypatch.setattr(pace, "_random_scalar", lambda _order: next(scalars))

    pace.perform_pace(picc.oid, b"\x03", b"\x0d")

    card_security = {"signature_valid": True, "security_infos": [_ca_spki(picc.domain, picc.domain.generator)]}
    assert pace.verify_cam(card_security)["chip_authentication_verified"] is True
