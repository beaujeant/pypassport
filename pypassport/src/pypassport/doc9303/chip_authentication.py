"""Chip Authentication v1/v2 for ICAO MRTDs and EAC national eIDs."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ
from Crypto.Random import get_random_bytes
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import Point

from pypassport.asn1 import to_asn1_length
from pypassport.doc9303.aes_secure_messaging import AesSecureMessaging
from pypassport.doc9303.secure_messaging import SecureMessaging
from pypassport.doc9303.domain_parameters import DHParameters, resolve as resolve_domain_parameters
from pypassport.doc9303.pace import _odd_parity
from pypassport.iso7816 import APDUCommand


class ChipAuthenticationError(Exception):
    pass


@dataclass(frozen=True)
class ChipAuthenticationResult:
    version: int
    oid: str
    key_id: int | None
    key_agreement: str
    cipher: str
    key_size: int
    terminal_public_key: bytes


def _tlv(tag, value):
    return bytes([tag]) + to_asn1_length(len(value)) + bytes(value)


def _suite(oid):
    parts = oid.split(".")
    if oid.startswith("0.4.0.127.0.7.2.2.3.1."):
        ka = "DH"
    elif oid.startswith("0.4.0.127.0.7.2.2.3.2."):
        ka = "ECDH"
    else:
        raise ChipAuthenticationError(f"Unknown Chip Authentication OID {oid}")
    suite = int(parts[-1])
    return (ka, "3DES", 112, 16, hashlib.sha1) if suite == 1 else (ka, "AES", {2:128,3:192,4:256}[suite], {2:16,3:24,4:32}[suite], hashlib.sha1 if suite == 2 else hashlib.sha256)


class ChipAuthentication:
    def __init__(self, iso7816):
        self.iso7816 = iso7816

    def perform(self, ca_info, public_key_info):
        version = int(ca_info.get("version", 2))
        if version not in (1, 2):
            raise ChipAuthenticationError(f"Unsupported Chip Authentication version {version}")
        oid = str(ca_info["protocol_oid"])
        ka, cipher, bits, key_len, hash_fn = _suite(oid)
        if version == 1 and cipher != "3DES":
            raise ChipAuthenticationError("Chip Authentication v1 is restricted to the 3DES suite")
        key_id = ca_info.get("key_id")
        if public_key_info.get("key_id") != key_id and None not in (public_key_info.get("key_id"), key_id):
            raise ChipAuthenticationError("ChipAuthenticationInfo and public key keyId do not match")

        peer, domain, public_width = self._public_key(public_key_info, ka)
        if ka == "ECDH":
            private = self._scalar(domain.order)
            terminal_public = self._ec_point_bytes(domain, domain.generator * private)
            if not domain.curve.contains_point(peer.x(), peer.y()) or peer * domain.order != domain.generator * 0:
                raise ChipAuthenticationError("CA public key is outside the negotiated EC subgroup")
            secret = self._int_bytes((peer * private).x(), public_width)
        else:
            private = self._scalar(domain.q or domain.p - 1)
            terminal_public = self._int_bytes(pow(domain.g, private, domain.p), public_width)
            if not 2 <= peer <= domain.p - 2 or domain.q and pow(peer, domain.q, domain.p) != 1:
                raise ChipAuthenticationError("CA public key is outside the negotiated DH subgroup")
            secret = self._int_bytes(pow(peer, private, domain.p), public_width)

        k_enc = hash_fn(secret + b"\x00\x00\x00\x01").digest()[:key_len]
        k_mac = hash_fn(secret + b"\x00\x00\x00\x02").digest()[:key_len]
        if cipher == "3DES":
            k_enc, k_mac = _odd_parity(k_enc), _odd_parity(k_mac)

        key_ref = (b"" if key_id is None or not ca_info.get("_include_key_reference")
                   else _tlv(0x84, self._int_bytes(key_id, max(1, (key_id.bit_length()+7)//8))))
        if version == 1:
            # CA v1 performs the ephemeral exchange in MSE:Set KAT.
            data = _tlv(0x91, terminal_public) + key_ref
            self.iso7816.transmit(APDUCommand("00", "22", "41", "A6", data=data), "CA v1 MSE:Set KAT")
        else:
            from pypassport.doc9303.access_control import _oid_to_der_value
            data = _tlv(0x80, _oid_to_der_value(oid)) + key_ref
            self.iso7816.transmit(APDUCommand("00", "22", "41", "A4", data=data), "CA v2 MSE:Set AT")
            ga_response = self.iso7816.transmit(
                APDUCommand("00", "86", "00", "00", data=_tlv(0x7C, _tlv(0x80, terminal_public)), le=256),
                "CA v2 General Authenticate",
            )
            if ga_response != b"\x7C\x00":
                raise ChipAuthenticationError("CA v2 General Authenticate response must be 7C00")

        self.iso7816.ciphering = (AesSecureMessaging(k_enc, k_mac, b"\x00" * 16)
                                  if cipher == "AES" else SecureMessaging(k_enc, k_mac, b"\x00" * 8))
        # CA is implicit authentication. A valid MAC under the fresh keys is
        # the first proof that the PICC possesses its authenticated static key.
        self.iso7816.get_challenge()
        logging.info("Chip Authentication v%d complete", version)
        result = ChipAuthenticationResult(version, oid, key_id, ka, cipher, bits, terminal_public)
        self.result = result
        return result

    def _scalar(self, order):
        width = (order.bit_length() + 7) // 8
        while True:
            value = int.from_bytes(get_random_bytes(width), "big") % order
            if value:
                return value

    @staticmethod
    def _int_bytes(value, width):
        return int(value).to_bytes(width, "big")

    @staticmethod
    def _ec_point_bytes(curve, point):
        width = (curve.curve.p().bit_length() + 7) // 8
        return b"\x04" + point.x().to_bytes(width, "big") + point.y().to_bytes(width, "big")

    def _public_key(self, info, ka):
        try:
            der = bytes.fromhex(info["public_key"]["spki_der_hex"])
            spki, rest = der_decode(der)
            if rest or der_encode(spki) != der:
                raise ValueError("non-canonical SPKI")
            params_der = der_encode(spki[0][1])
            key_bytes = spki[1].asOctets()
            if ka == "ECDH":
                params, trailing = der_decode(params_der)
                if not trailing and isinstance(params, univ.Sequence) and len(params) >= 2 and str(params[0]) == "0.4.0.127.0.7.1.2":
                    domain = resolve_domain_parameters("ECDH", int(params[1]))
                else:
                    domain = Curve.from_der(params_der)
                width = (domain.curve.p().bit_length() + 7) // 8
                if len(key_bytes) != 1 + width * 2 or key_bytes[0] != 4:
                    raise ValueError("CA ECDH point must be uncompressed and full width")
                return Point(domain.curve, int.from_bytes(key_bytes[1:1+width], "big"),
                             int.from_bytes(key_bytes[1+width:], "big"), domain.order), domain, width
            values, rest = der_decode(params_der, asn1Spec=univ.Sequence())
            if rest or len(values) < 2:
                raise ValueError("invalid DH parameters")
            if str(values[0]) == "0.4.0.127.0.7.1.2":
                domain = resolve_domain_parameters("DH", int(values[1]))
                public, rest = der_decode(key_bytes, asn1Spec=univ.Integer())
                return int(public), domain, domain.width
            domain = DHParameters(int(values[0]), int(values[1]), int(values[2]) if len(values)>2 else None)
            public, rest = der_decode(key_bytes, asn1Spec=univ.Integer())
            return int(public), domain, domain.width
        except Exception as exc:
            raise ChipAuthenticationError(f"Cannot decode CA public key: {exc}") from exc


def select_chip_authentication_pair(infos, key_id=None):
    protocols = [x for x in infos if str(x.get("protocol_oid", "")).startswith("0.4.0.127.0.7.2.2.3.")]
    keys = [x for x in infos if str(x.get("protocol_oid", "")).startswith("0.4.0.127.0.7.2.2.1.")]
    pairs = [(protocol, key) for protocol in protocols for key in keys
             if protocol.get("key_id") == key.get("key_id") or len(protocols) == len(keys) == 1]
    if key_id is not None:
        pairs = [x for x in pairs if x[0].get("key_id") == key_id]
    if not pairs:
        raise ChipAuthenticationError("No unambiguous Chip Authentication protocol/public-key pair")
    pairs.sort(key=lambda x: (int(x[0]["protocol_oid"].split(".")[-1]), x[0].get("version", 0)), reverse=True)
    selected_protocol = dict(pairs[0][0])
    selected_protocol["_include_key_reference"] = len(keys) > 1
    return selected_protocol, pairs[0][1]
