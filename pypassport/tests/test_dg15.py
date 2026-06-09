"""Tests for DG15 (Active Authentication Public Key Info) reading."""

import pytest
from unittest.mock import MagicMock, patch, call

from pypassport.doc9303 import converter
from pypassport.doc9303.data_group import (
    DataGroup15,
    ElementaryFileException,
    readElementaryFile,
)
from pypassport.iso7816 import ISO7816Exception


# ---------------------------------------------------------------------------
# Converter / FID mapping
# ---------------------------------------------------------------------------


def test_dg15_tag():
    assert converter.toTAG("DG15") == "6F"


def test_dg15_fid():
    """EF.DG15 file identifier must be 0115 per ICAO 9303 Part 10."""
    assert converter.toFID("DG15") == "0115"


def test_dg15_fid_from_tag():
    """Same FID whether we look up by DG name or by tag."""
    assert converter.toFID("6F") == "0115"


def test_dg16_fid():
    """EF.DG16 file identifier must be 0116 per ICAO 9303 Part 10."""
    assert converter.toFID("DG16") == "0116"


def test_dg14_fid_unaffected():
    """DG14 FID should remain 010E (sequential with DG1-DG14)."""
    assert converter.toFID("DG14") == "010E"


# ---------------------------------------------------------------------------
# readElementaryFile selects the correct FID for DG15
# ---------------------------------------------------------------------------


class FakeISO7816:
    """Minimal ISO7816 stand-in that records SELECT calls and returns canned data."""

    def __init__(self, dg_bytes):
        self.ciphering = False
        self.selected_fid = None
        self._dg_bytes = dg_bytes
        self._offset = 0

    def selectElementaryFile(self, fid):
        self.selected_fid = fid

    def readBinary(self, offset, length):
        chunk = self._dg_bytes[offset: offset + length]
        return bytes(chunk)


def _minimal_dg15_bytes(spki_der: bytes) -> bytes:
    """Wrap raw SubjectPublicKeyInfo DER in the DG15 outer TLV (tag 6F)."""
    length = len(spki_der)
    if length <= 0x7F:
        return bytes([0x6F, length]) + spki_der
    elif length <= 0xFF:
        return bytes([0x6F, 0x81, length]) + spki_der
    else:
        return bytes([0x6F, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + spki_der


# Minimal (but valid-looking) SubjectPublicKeyInfo DER for RSA-1024.
# This is a stripped-down placeholder: tag 30 (SEQUENCE), short length,
# two nested objects.  The DataGroup15 parser is called in __init__ and
# any parse failure is caught/warned so the raw bytes are always stored.
_FAKE_SPKI = bytes([
    0x30, 0x0D,                                        # SEQUENCE (13)
    0x30, 0x09,                                        # AlgorithmIdentifier
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,  # OID ecPublicKey
    0x03, 0x00,                                        # BIT STRING (empty placeholder)
])


def test_readElementaryFile_selects_dg15_fid_0115():
    """readElementaryFile must SELECT FID 0115 when reading tag 6F / DG15."""
    dg_bytes = _minimal_dg15_bytes(_FAKE_SPKI)
    iso = FakeISO7816(dg_bytes)

    # DataGroup15 parse may fail (placeholder SPKI), but the raw bytes are kept.
    readElementaryFile("DG15", iso)

    assert iso.selected_fid == "0115", (
        f"Expected FID 0115 for DG15 but got {iso.selected_fid!r}. "
        "Wrong FID causes the chip to return SW 6882 (Secure messaging not supported)."
    )


def test_readElementaryFile_selects_dg15_by_tag():
    """Same test but using the raw tag '6F' as input."""
    dg_bytes = _minimal_dg15_bytes(_FAKE_SPKI)
    iso = FakeISO7816(dg_bytes)

    readElementaryFile("6F", iso)

    assert iso.selected_fid == "0115"


# ---------------------------------------------------------------------------
# DG15 read uses active SM session (not a separate code path)
# ---------------------------------------------------------------------------


def test_dg15_uses_sm_session(monkeypatch):
    """
    readElementaryFile must go through iso7816.selectElementaryFile and
    iso7816.readBinary, which use the active ciphering object.  We verify
    that when ciphering is set the same object is used for DG15 just as for
    DG1/DG2.
    """
    dg_bytes = _minimal_dg15_bytes(_FAKE_SPKI)

    iso = MagicMock()
    iso.ciphering = object()  # simulate active SM session

    # readBinary needs to return 4 bytes first (header) then the rest
    header = dg_bytes[:2]  # tag + 1-byte length (for our short test DG)
    # Build a proper header read (4 bytes) that matches the actual bytes
    iso.readBinary.side_effect = [
        dg_bytes[:4],       # header read
        dg_bytes[2:],       # body read (all remaining after header)
    ]

    readElementaryFile("DG15", iso)

    iso.selectElementaryFile.assert_called_once_with("0115")
    assert iso.readBinary.call_count >= 1


# ---------------------------------------------------------------------------
# DataGroup15 raw fallback
# ---------------------------------------------------------------------------


def test_dg15_stores_raw_body():
    """If SubjectPublicKeyInfo parse fails, raw body bytes must still be stored."""
    spki_garbage = b"\xFF\xFF\xFF\xFF"
    dg_bytes = _minimal_dg15_bytes(spki_garbage)
    dg = DataGroup15(file=dg_bytes)

    assert "raw" in dg
    assert dg["raw"] == spki_garbage


def test_dg15_parse_failure_does_not_raise():
    """A broken SPKI must not propagate an exception — warn only."""
    spki_garbage = b"\x00\x01\x02\x03"
    dg_bytes = _minimal_dg15_bytes(spki_garbage)
    dg = DataGroup15(file=dg_bytes)  # must not raise
    assert dg is not None


def test_dg15_raw_outer_tag_6f_accepted():
    """DG15 file with outer tag 0x6F is parsed without error."""
    spki = _FAKE_SPKI
    dg_bytes = _minimal_dg15_bytes(spki)
    assert dg_bytes[0] == 0x6F, "Outer tag should be 0x6F"
    dg = DataGroup15(file=dg_bytes)
    assert dg is not None


# ---------------------------------------------------------------------------
# EPassport.__getitem__ error message is not "Secure messaging not supported"
# when SM is active and chip returns an error reading DG15
# ---------------------------------------------------------------------------


def test_dg15_chip_error_message_includes_sw(caplog):
    """
    When SM is active and the chip returns a non-success SW for DG15,
    the logged message must include the SW values, not the ambiguous
    'Secure messaging not supported' string by itself.
    """
    import logging
    from pypassport.epassport import EPassport

    fake_iso = MagicMock()
    fake_iso.ciphering = object()  # SM active

    # Simulate chip returning SW 6882 (Secure messaging not supported)
    sm_err = ISO7816Exception("Secure messaging not supported", 0x68, 0x82)

    with patch("pypassport.epassport.readElementaryFile", side_effect=sm_err), \
         caplog.at_level(logging.ERROR, logger="pypassport.epassport"):

        # Build a minimal EPassport-like object without hitting __init__ by
        # subclassing dict directly and manually assigning the attributes the
        # __getitem__ method needs.
        class _FakeEP(EPassport):
            def __init__(self):  # skip the real __init__
                pass

        ep = _FakeEP()
        ep.iso7816 = fake_iso

        # converter.toTAG("DG15") returns "6F"; "6F" not in ep (empty dict).
        result = ep["DG15"]

    assert result is None
    assert any("6882" in r.message or "SW=6882" in r.message for r in caplog.records), (
        "Error log must include SW=6882 so the developer knows this is a chip error, "
        "not a missing SM session. Got: " + str([r.message for r in caplog.records])
    )


# ---------------------------------------------------------------------------
# AES SM SSC synchronisation
# ---------------------------------------------------------------------------
# These tests cover the cascading-6882 failure: after a DG read fails, the
# Send Sequence Counter (SSC) must remain synchronised with the chip so that
# subsequent DG reads are not rejected.


from pypassport.doc9303.aes_secure_messaging import AesSecureMessaging, AesSecureMessagingException
from pypassport.iso7816 import APDUCommand, APDUResponse
from Crypto.Cipher import AES as _AES
from Crypto.Hash import CMAC as _CMAC


_K_ENC = bytes.fromhex("AB94FDECF2674FDFB9B391F85D7F76F2")
_K_MAC = bytes.fromhex("7962D9ECE03D1ACD4C76089DCE131543")
_SSC0  = b"\x00" * 16


def _make_sm():
    return AesSecureMessaging(_K_ENC, _K_MAC, _SSC0)


def _build_valid_sm_response(command_ssc: bytes, plain_data: bytes,
                              inner_sw: bytes = b"\x90\x00") -> "APDUResponse":
    """
    Build a well-formed AES SM response for a chip that received a command at
    *command_ssc*.  The chip increments SSC once more for the response send,
    so the response MAC is computed at command_ssc + 1.
    Returns a raw APDUResponse with outer SW=9000.
    """
    from pypassport.doc9303.aes_secure_messaging import _iso_pad
    # Chip increments SSC for the response (one more than the command SSC).
    ssc = (int.from_bytes(command_ssc, "big") + 1).to_bytes(16, "big")

    if plain_data:
        iv = _AES.new(_K_ENC, _AES.MODE_ECB).encrypt(ssc)
        cipher = _AES.new(_K_ENC, _AES.MODE_CBC, iv).encrypt(_iso_pad(plain_data))
        do87 = b"\x87" + bytes([len(cipher) + 1]) + b"\x01" + cipher
    else:
        do87 = b""

    do99 = b"\x99\x02" + inner_sw

    K = _iso_pad(ssc + do87 + do99)
    c = _CMAC.new(_K_MAC, ciphermod=_AES)
    c.update(K)
    do8e = b"\x8E\x08" + c.digest()[:8]

    body = do87 + do99 + do8e
    return APDUResponse(body, 0x90, 0x00)


def test_ssc_unchanged_after_plain_error_response():
    """
    When the chip returns a plain (non-SM-wrapped) error, the client SSC must
    remain at the post-protect value.  Many chips verify the SM MAC (advancing
    their SSC for receive) before returning a plain application error, so both
    sides end up at the same SSC value if the client does not decrement.
    """
    sm = _make_sm()
    cmd = APDUCommand("00", "B0", "00", "00", le="04")

    sm.protect(cmd)
    ssc_after_protect = sm._ssc

    plain_err = APDUResponse(b"", 0x68, 0x82)
    sm.unprotect(plain_err)

    assert sm._ssc == ssc_after_protect, (
        "SSC must not change after a plain error response. "
        f"Got {sm._ssc.hex()!r}, expected {ssc_after_protect.hex()!r}."
    )


def test_ssc_incremented_early_when_sm_response_parsing_fails():
    """
    If the chip sends an SM-wrapped response (outer 9000) but the inner
    DO'8E' is missing, unprotect raises AesSecureMessagingException.
    The client SSC must have been incremented BEFORE the exception so that
    the chip and client remain in sync for the next command.
    """
    sm = _make_sm()
    cmd = APDUCommand("00", "B0", "00", "00", le="04")
    sm.protect(cmd)
    ssc_before = sm._ssc  # SSC after protect

    # Build a response with outer 9000 but without DO'8E' (malformed).
    do99 = b"\x99\x02\x90\x00"
    rapdu = APDUResponse(do99, 0x90, 0x00)  # no DO'8E'

    with pytest.raises(AesSecureMessagingException, match="DO8E missing"):
        sm.unprotect(rapdu)

    # SSC should have been incremented before the exception.
    expected_ssc = (int.from_bytes(ssc_before, "big") + 1).to_bytes(16, "big")
    assert sm._ssc == expected_ssc, (
        "SSC must be incremented before parsing exceptions to stay in sync with "
        f"the chip. Got {sm._ssc.hex()!r}, expected {expected_ssc.hex()!r}."
    )
