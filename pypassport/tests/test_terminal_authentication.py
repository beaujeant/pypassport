"""CVC path and host-side Terminal Authentication transcript coverage."""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from pypassport.asn1 import to_asn1_length
from pypassport.doc9303.pace import _oid_value
from pypassport.doc9303.terminal_authentication import CVCError, CVCertificate, TerminalAuthentication, parse_ef_cvca, validate_cvc_chain


RSA_SHA256 = "0.4.0.127.0.7.2.2.2.1.2"
CHAT = "0.4.0.127.0.7.3.1.2.1"


def _tlv(tag, value):
    encoded_tag = bytes.fromhex(tag)
    return encoded_tag + to_asn1_length(len(value)) + value


def _certificate(subject_ref, issuer_ref, role, rights, subject_key, issuer_key):
    role_bits = {"IS": 0, "DV-foreign": 1, "DV-domestic": 2, "CVCA": 3}[role] << 6
    public_key = _tlv("06", _oid_value(RSA_SHA256))
    public_key += _tlv("81", subject_key.n.to_bytes((subject_key.n.bit_length() + 7) // 8, "big"))
    public_key += _tlv("82", subject_key.e.to_bytes((subject_key.e.bit_length() + 7) // 8, "big"))
    chat = _tlv("06", _oid_value(CHAT)) + _tlv("53", bytes([role_bits | rights]))
    body = _tlv("5F29", b"\x00") + _tlv("42", issuer_ref) + _tlv("5F20", subject_ref)
    body += _tlv("7F49", public_key) + _tlv("7F4C", chat)
    body += _tlv("5F25", bytes([2, 5, 0, 1, 0, 1])) + _tlv("5F24", bytes([2, 7, 1, 2, 3, 1]))
    body_tlv = _tlv("7F4E", body)
    signature = pkcs1_15.new(issuer_key).sign(SHA256.new(body_tlv))
    return _tlv("7F21", body_tlv + _tlv("5F37", signature))


class _TerminalTranscript:
    def __init__(self, public_key, id_picc):
        self.public_key = public_key
        self.id_picc = id_picc
        self.challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        self.commands = []

    def transmit(self, command, message):
        self.commands.append((command, message))
        if command.ins == "82":
            signature = bytes.fromhex(command.data)
            pkcs1_15.new(self.public_key).verify(SHA256.new(self.id_picc + self.challenge), signature)
        return b""

    def transmit_chained(self, command, source):
        self.commands.append((command, source))
        return b""

    def get_challenge(self):
        return self.challenge


def test_cvca_chain_and_terminal_authentication_apdu_transcript():
    cvca_key, dv_key, terminal_key = (RSA.generate(1024) for _ in range(3))
    cvca_ref, dv_ref, terminal_ref = b"CVCA00001", b"DVA000001", b"IS0000001"
    cvca = _certificate(cvca_ref, cvca_ref, "CVCA", 3, cvca_key, cvca_key)
    dv = _certificate(dv_ref, cvca_ref, "DV-domestic", 3, dv_key, cvca_key)
    terminal = _certificate(terminal_ref, dv_ref, "IS", 1, terminal_key, dv_key)

    parsed_terminal = CVCertificate.parse(terminal)
    assert parsed_terminal.rights == {"read_dg3": True, "read_dg4": False, "raw": "01"}
    assert [cert.role for cert in validate_cvc_chain([terminal, dv], [cvca])] == ["IS", "DV-domestic", "CVCA"]

    id_picc = b"document-id"
    transcript = _TerminalTranscript(terminal_key.publickey(), id_picc)
    result = TerminalAuthentication(transcript).perform(
        [terminal, dv], terminal_key.export_key(format="DER"), [cvca_ref], id_picc
    )
    assert result["terminal"] == terminal_ref.decode()
    assert [command.ins for command, _message in transcript.commands] == ["22", "2A", "22", "2A", "22", "82"]


def test_cvc_rejects_chat_right_escalation():
    cvca_key, dv_key, terminal_key = (RSA.generate(1024) for _ in range(3))
    cvca = _certificate(b"CVCA00001", b"CVCA00001", "CVCA", 1, cvca_key, cvca_key)
    dv = _certificate(b"DVA000001", b"CVCA00001", "DV-domestic", 1, dv_key, cvca_key)
    terminal = _certificate(b"IS0000001", b"DVA000001", "IS", 3, terminal_key, dv_key)
    try:
        validate_cvc_chain([terminal, dv], [cvca])
    except CVCError as exc:
        assert "grants CHAT rights" in str(exc)
    else:
        raise AssertionError("CHAT right escalation was accepted")


def test_parse_ef_cvca_accepts_current_and_previous_references():
    assert parse_ef_cvca(_tlv("42", b"current") + _tlv("42", b"previous")) == [b"current", b"previous"]
