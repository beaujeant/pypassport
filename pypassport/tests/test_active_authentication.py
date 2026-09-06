"""Tests for native (OpenSSL-free) Active Authentication.

Active Authentication recovers an ISO 9796-2 message from a raw RSA signature
(formerly ``openssl rsautl -raw``). We build a valid signature for a known
RSA key and challenge and drive the full ``execute_aa`` flow.
"""

import hashlib


from Crypto.PublicKey import RSA
from ecdsa import BRAINPOOLP256r1, NIST256p, SigningKey
from ecdsa.util import sigencode_der, sigencode_string

from pypassport.doc9303 import cms
from pypassport.doc9303 import active_authentication
from pypassport.doc9303.active_authentication import (
    ActiveAuthentication,
)


def _rsa_sign_raw(key, block):
    s = pow(int.from_bytes(block, "big"), key.d, key.n)
    size = (key.n.bit_length() + 7) // 8
    return s.to_bytes(size, "big")


def _iso9796_block(key, m1, rnd):
    """Build an ISO 9796-2 scheme-1 (SHA-1) recoverable-message block."""
    size = (key.n.bit_length() + 7) // 8
    digest = hashlib.sha1(m1 + rnd).digest()
    block = b"\x6a" + m1 + digest + b"\xbc"
    assert len(block) == size
    return block


def test_rsa_recover_round_trip():
    key = RSA.generate(1024)
    spki = key.publickey().export_key(format="DER")
    size = (key.n.bit_length() + 7) // 8
    block = b"\x6a" + b"\x42" * (size - 2) + b"\xbc"
    sig = _rsa_sign_raw(key, block)
    assert cms.rsa_recover(spki, sig) == block


class _FakeISO7816:
    def __init__(self, signature):
        self._signature = signature

    def internal_authentication(self, challenge_hex):
        return self._signature


class _FakeDG15:
    def __init__(self, body):
        self.body = body


def _setup(monkeypatch, rnd_used_for_signature, rnd_seen_by_reader):
    key = RSA.generate(1024)
    spki = key.publickey().export_key(format="DER")
    size = (key.n.bit_length() + 7) // 8
    m1 = b"\xa5" * (size - 22)
    block = _iso9796_block(key, m1, rnd_used_for_signature)
    signature = _rsa_sign_raw(key, block)

    monkeypatch.setattr(active_authentication.Random, "get_random_bytes", lambda n: rnd_seen_by_reader)
    aa = ActiveAuthentication(_FakeISO7816(signature))
    return aa, _FakeDG15(spki)


def test_execute_aa_success(monkeypatch):
    rnd = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    aa, dg15 = _setup(monkeypatch, rnd, rnd)
    assert aa.execute_aa(dg15) is True


def test_execute_aa_wrong_challenge(monkeypatch):
    # The signature was computed for one RND; the reader uses a different one,
    # so the recovered digest must not match.
    aa, dg15 = _setup(monkeypatch, b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\xff\xff\xff\xff\xff\xff\xff\xff")
    assert aa.execute_aa(dg15) is False


def test_get_pub_key_returns_pem():
    key = RSA.generate(1024)
    spki = key.publickey().export_key(format="DER")
    pem = cms.public_key_to_pem(spki)
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")


# --- ECDSA Active Authentication (Brainpool, named and explicit params) ------


def _setup_ecdsa(
    monkeypatch,
    curve,
    rnd_used,
    rnd_seen,
    *,
    params_encoding="named_curve",
    sigencode=sigencode_string,
    hashfunc=hashlib.sha256,
):
    sk = SigningKey.generate(curve=curve)
    spki = sk.get_verifying_key().to_der(curve_parameters_encoding=params_encoding)
    signature = sk.sign(rnd_used, hashfunc=hashfunc, sigencode=sigencode)
    monkeypatch.setattr(active_authentication.Random, "get_random_bytes", lambda n: rnd_seen)
    aa = ActiveAuthentication(_FakeISO7816(signature))
    return aa, _FakeDG15(spki)


def test_execute_aa_ecdsa_brainpool_success(monkeypatch):
    rnd = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    aa, dg15 = _setup_ecdsa(monkeypatch, BRAINPOOLP256r1, rnd, rnd)
    assert aa.execute_aa(dg15) is True


def test_execute_aa_ecdsa_explicit_params_success(monkeypatch):
    # The exact shape of a Belgian passport's DG15: EC key with *explicit*
    # domain parameters, which pycryptodome cannot parse at all.
    rnd = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    aa, dg15 = _setup_ecdsa(monkeypatch, BRAINPOOLP256r1, rnd, rnd, params_encoding="explicit")
    assert aa.execute_aa(dg15) is True


def test_execute_aa_ecdsa_der_signature_success(monkeypatch):
    # Some chips DER-encode the AA signature instead of using plain r||s.
    rnd = b"\x09\x09\x09\x09\x09\x09\x09\x09"
    aa, dg15 = _setup_ecdsa(monkeypatch, NIST256p, rnd, rnd, sigencode=sigencode_der)
    assert aa.execute_aa(dg15) is True


def test_execute_aa_ecdsa_wrong_challenge(monkeypatch):
    aa, dg15 = _setup_ecdsa(
        monkeypatch, BRAINPOOLP256r1, b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\xff\xff\xff\xff\xff\xff\xff\xff"
    )
    assert aa.execute_aa(dg15) is False


def test_execute_aa_ecdsa_hash_from_dg14(monkeypatch):
    # DG14 ActiveAuthenticationInfo naming SHA-384 must drive verification even
    # though the curve-size default for P-256 would be SHA-256.
    rnd = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
    aa, dg15 = _setup_ecdsa(monkeypatch, BRAINPOOLP256r1, rnd, rnd, hashfunc=hashlib.sha384)
    dg14 = _FakeDG15(_dg14_with_aa_sig_oid("1.2.840.10045.4.3.3"))  # ecdsa-with-SHA384
    assert aa.execute_aa(dg15, dg14) is True


def test_execute_aa_ecdsa_bsi_plain_sha512_from_dg14(monkeypatch):
    rnd = b"\x10\x20\x30\x40\x50\x60\x70\x80"
    aa, dg15 = _setup_ecdsa(monkeypatch, BRAINPOOLP256r1, rnd, rnd, hashfunc=hashlib.sha512)
    dg14 = _FakeDG15(_dg14_with_aa_sig_oid("0.4.0.127.0.7.1.1.4.1.5"))
    assert aa.execute_aa(dg15, dg14, strict=True) is True


def _dg14_with_aa_sig_oid(sig_oid):
    """Build a minimal DG14 SecurityInfos body with one ActiveAuthenticationInfo.

    SET { SEQUENCE { OID aaProtocolObject, INTEGER version, OID signatureAlgorithm } }
    """
    from pyasn1.codec.der.encoder import encode as der_encode
    from pyasn1.type import univ

    info = univ.Sequence()
    info.setComponentByPosition(0, univ.ObjectIdentifier("2.23.136.1.1.5"))
    info.setComponentByPosition(1, univ.Integer(1))
    info.setComponentByPosition(2, univ.ObjectIdentifier(sig_oid))
    security_infos = univ.SetOf()
    security_infos.setComponentByPosition(0, info)
    return der_encode(security_infos)
