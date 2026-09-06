import hashlib

import pytest
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ
from ecdsa.ellipticcurve import Point

from pypassport.doc9303.aes_secure_messaging import AesSecureMessaging
from pypassport.doc9303.chip_authentication import ChipAuthentication
from pypassport.doc9303.domain_parameters import DHParameters, resolve
from pypassport.doc9303.pace import _odd_parity
from pypassport.doc9303.secure_messaging import SecureMessaging


def _spki(agreement, parameter_id, public):
    parameters = univ.Sequence()
    parameters.setComponentByPosition(0, univ.ObjectIdentifier("0.4.0.127.0.7.1.2"))
    parameters.setComponentByPosition(1, univ.Integer(parameter_id))
    algorithm = univ.Sequence()
    algorithm.setComponentByPosition(0, univ.ObjectIdentifier(f"0.4.0.127.0.7.2.2.1.{1 if agreement == 'DH' else 2}"))
    algorithm.setComponentByPosition(1, parameters)
    spki = univ.Sequence()
    spki.setComponentByPosition(0, algorithm)
    encoded_public = der_encode(univ.Integer(public)) if agreement == "DH" else public
    spki.setComponentByPosition(1, univ.BitString.fromOctetString(encoded_public))
    return {"protocol_oid": str(algorithm[0]), "key_id": 7, "public_key": {"spki_der_hex": der_encode(spki).hex()}}


class _Transcript:
    def __init__(self):
        self.ciphering = None
        self.commands = []

    def transmit(self, command, message):
        self.commands.append((command, message))
        return b"\x7c\x00" if command.ins == "86" else b""

    def get_challenge(self):
        assert self.ciphering is not None
        return b"proof"


@pytest.mark.parametrize(
    ("agreement", "version", "suite"),
    [(agreement, version, suite) for agreement in ("DH", "ECDH") for version, suite in ((1, 1), (2, 1), (2, 2), (2, 3), (2, 4))],
)
def test_ca_v1_v2_profile_transcript_and_two_party_keys(monkeypatch, agreement, version, suite):
    parameter_id = 0 if agreement == "DH" else 13
    domain = resolve(agreement, parameter_id)
    static_private, terminal_private = 7, 11
    if isinstance(domain, DHParameters):
        static_public = pow(domain.g, static_private, domain.p)
    else:
        static_public = ChipAuthentication._ec_point_bytes(domain, domain.generator * static_private)
    oid = f"0.4.0.127.0.7.2.2.3.{1 if agreement == 'DH' else 2}.{suite}"
    ca_info = {"protocol_oid": oid, "version": version, "key_id": 7, "_include_key_reference": True}
    transcript = _Transcript()
    ca = ChipAuthentication(transcript)
    monkeypatch.setattr(ca, "_scalar", lambda _order: terminal_private)

    result = ca.perform(ca_info, _spki(agreement, parameter_id, static_public))

    if isinstance(domain, DHParameters):
        terminal_public = int.from_bytes(result.terminal_public_key, "big")
        shared = pow(terminal_public, static_private, domain.p).to_bytes(domain.width, "big")
    else:
        width = (domain.curve.p().bit_length() + 7) // 8
        encoded = result.terminal_public_key
        point = Point(
            domain.curve,
            int.from_bytes(encoded[1:1 + width], "big"),
            int.from_bytes(encoded[1 + width:], "big"),
            domain.order,
        )
        shared = (point * static_private).x().to_bytes(width, "big")
    key_len = {1: 16, 2: 16, 3: 24, 4: 32}[suite]
    digest = hashlib.sha1 if suite in (1, 2) else hashlib.sha256
    expected_enc = digest(shared + b"\0\0\0\1").digest()[:key_len]
    expected_mac = digest(shared + b"\0\0\0\2").digest()[:key_len]
    if suite == 1:
        expected_enc, expected_mac = _odd_parity(expected_enc), _odd_parity(expected_mac)
        assert isinstance(transcript.ciphering, SecureMessaging)
    else:
        assert isinstance(transcript.ciphering, AesSecureMessaging)
    assert transcript.ciphering._ksenc == expected_enc
    assert transcript.ciphering._ksmac == expected_mac
    assert len(transcript.commands) == (1 if version == 1 else 2)
    assert transcript.commands[0][0].p2 == ("A6" if version == 1 else "A4")
    if version == 2:
        assert transcript.commands[1][0].ins == "86"
