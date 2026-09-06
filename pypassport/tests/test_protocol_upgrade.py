import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ

from pypassport.asn1 import asn1_length, to_asn1_length
from pypassport.doc9303.aes_secure_messaging import AesSecureMessaging, AesSecureMessagingException
from pypassport.doc9303.file_context import MF, resolve_file
from pypassport.doc9303.file_system import FileSystemExplorer
from pypassport.doc9303.pace import PACE
from pypassport.doc9303.security_info import PACEInfo
from pypassport.iso7816 import APDUCommand, APDUResponse, ISO7816


class _Reader:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def transmit(self, request):
        self.requests.append(bytes(request))
        return self.responses.pop(0)


def test_short_and_extended_apdu_roundtrip():
    commands = [
        APDUCommand("00", "84", "00", "00", le=256),
        APDUCommand("00", "B0", "00", "00", le=65536),
        APDUCommand("00", "86", "00", "00", data=bytes(range(256)), le=65536),
    ]
    for command in commands:
        assert APDUCommand.from_bytes(bytes(command.raw())).raw() == command.raw()


def test_iso_procedure_bytes_and_partial_data():
    reader = _Reader([(b"", 0x6C, 4), (b"ABCD", 0x90, 0), (b"A", 0x61, 2), (b"BC", 0x90, 0),
                      (b"partial", 0x62, 0x82)])
    iso = ISO7816(reader)
    assert iso.transmit(APDUCommand("00", "B0", "00", "00", le=8)) == b"ABCD"
    assert iso.transmit(APDUCommand("00", "CA", "00", "00", le=256)) == b"ABC"
    assert iso.transmit(APDUCommand("00", "B0", "00", "00", le=16)) == b"partial"
    assert reader.requests[1][-1] == 4


def test_secure_messaging_never_accepts_bare_success():
    sm = AesSecureMessaging(bytes(16), bytes.fromhex("01010101010101010101010101010101"), bytes(16))
    with pytest.raises(AesSecureMessagingException):
        sm.unprotect(APDUResponse(b"secret", 0x90, 0))


def test_file_reference_needs_application_for_colliding_fid():
    with pytest.raises(KeyError, match="Ambiguous"):
        resolve_file("011D")
    assert resolve_file("011D", application=MF).name == "CardSecurity"


def test_filesystem_reads_explicit_application_qualified_fid():
    class FakeISO:
        raw = b"\x53\x05hello"

        def select_context(self, reference):
            self.reference = reference

        def read_binary(self, offset, length):
            return self.raw[offset:offset + length]

    iso = FakeISO()
    ef = FileSystemExplorer(iso).read_file("A00000024710FE", "BEEF")
    assert iso.reference.application == "A00000024710FE" and iso.reference.fid == "BEEF"
    assert ef.file == iso.raw


def test_asn1_long_lengths_roundtrip():
    for value in (128, 65536, 0xFFFFFF):
        encoded = to_asn1_length(value)
        assert asn1_length(encoded) == (value, len(encoded))


def test_pace_capability_matches_runtime_profiles():
    assert PACEInfo("0.4.0.127.0.7.2.2.4.1.2", 2, 0).is_supported()
    assert PACEInfo("0.4.0.127.0.7.2.2.4.4.4", 2, 13).is_supported()
    assert not PACEInfo("0.4.0.127.0.7.2.2.4.4.4", 2, 10).is_supported()
    assert not PACEInfo("0.4.0.127.0.7.2.2.4.2.2", 1, 13).is_supported()
    pace = PACE(object(), password=b"123456")
    assert pace.password_reference is None


def test_pace_integrated_mapping_icao_known_answer():
    pace = PACE(object(), password=b"x")
    pace._key_agreement, pace._mapping, pace._cipher, pace._key_len = "ECDH", "IM", "AES", 16
    pace._configure_domain(13, None)
    pace._get_im_x2(bytes.fromhex("2923BE84E16CD6AE529049F1F1BBE9EB"),
                    bytes.fromhex("5DD4CBFC96F5453B130D890A1CDBAE32"))
    assert f"{pace._PACE__g_prime.x():064X}" == "8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427"
    assert f"{pace._PACE__g_prime.y():064X}" == "4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD"


def test_pace_cam_binds_mapping_key_to_cardsecurity():
    pace = PACE(object(), password=b"x")
    pace._key_agreement, pace._mapping, pace._cipher, pace._key_len = "ECDH", "CAM", "AES", 16
    pace._configure_domain(13, None)
    static_private, ca_scalar = 7, 11
    static_public = pace.pointG * static_private
    mapping_public = static_public * ca_scalar
    pace._cam_mapping_public_key = bytes(pace._point_to_bytes(mapping_public))
    pace._pace_k_enc = bytes(range(16))
    iv = AES.new(pace._pace_k_enc, AES.MODE_ECB).encrypt(b"\xFF" * 16)
    plain = ca_scalar.to_bytes(32, "big")
    pace._cam_encrypted_data = AES.new(pace._pace_k_enc, AES.MODE_CBC, iv).encrypt(pad(plain, 16, style="iso7816"))

    parameters = univ.Sequence()
    parameters.setComponentByPosition(0, univ.ObjectIdentifier("0.4.0.127.0.7.1.2"))
    parameters.setComponentByPosition(1, univ.Integer(13))
    algorithm = univ.Sequence()
    algorithm.setComponentByPosition(0, univ.ObjectIdentifier("0.4.0.127.0.7.1.2"))
    algorithm.setComponentByPosition(1, parameters)
    spki = univ.Sequence()
    spki.setComponentByPosition(0, algorithm)
    spki.setComponentByPosition(1, univ.BitString.fromOctetString(bytes(pace._point_to_bytes(static_public))))
    card_security = {
        "signature_valid": True,
        "security_infos": [{"protocol_oid": "0.4.0.127.0.7.2.2.1.2", "key_id": 13,
                            "public_key": {"spki_der_hex": der_encode(spki).hex()}}],
    }
    assert pace.verify_cam(card_security)["chip_authentication_verified"] is True
