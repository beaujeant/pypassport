"""Security-focused regression tests for secure messaging helpers."""

from pypassport.doc9303.secure_messaging import SecureMessaging


def test_string_representation_redacts_session_keys():
    sm = SecureMessaging(b"\x01" * 16, b"\x02" * 16, b"\x03" * 8)

    text = str(sm)

    assert "KSenc: [REDACTED]" in text
    assert "KSmac: [REDACTED]" in text
    assert "01010101" not in text
    assert "02020202" not in text
    assert "SSC: 0303030303030303" in text
