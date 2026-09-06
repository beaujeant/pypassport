"""CVC parsing, EAC role validation, and optional Terminal Authentication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib

from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import CurveFp, Point
from ecdsa.util import sigencode_string, sigdecode_string

from pypassport.asn1 import to_asn1_length
from pypassport.doc9303.security_info import _decode_oid_bytes
from pypassport.iso7816 import APDUCommand
from pypassport.utils import parse_tlv


class CVCError(Exception):
    pass


def _tlv(tag, value):
    tag_bytes = bytes.fromhex(tag) if isinstance(tag, str) else bytes([tag])
    return tag_bytes + to_asn1_length(len(value)) + bytes(value)


def _children(value):
    children, offset = {}, 0
    while offset < len(value):
        tag, child, consumed = parse_tlv(value[offset:])
        if tag in children:
            raise CVCError(f"Duplicate CVC data object {tag}")
        children[tag] = (child, value[offset:offset + consumed])
        offset += consumed
    return children


def _cvc_date(value):
    if len(value) != 6 or any(x > 9 for x in value):
        raise CVCError("CVC dates must contain six numeric octets")
    year = 2000 + value[0] * 10 + value[1]
    return date(year, value[2] * 10 + value[3], value[4] * 10 + value[5])


@dataclass(frozen=True)
class CVCertificate:
    encoded: bytes
    body_der: bytes
    car: bytes
    chr: bytes
    effective: date
    expiration: date
    public_key_oid: str
    public_key_objects: dict[str, bytes]
    chat_oid: str
    authorization: bytes
    signature: bytes

    @property
    def role(self):
        bits = self.authorization[0] >> 6 if self.authorization else 0
        return ("IS", "DV-foreign", "DV-domestic", "CVCA")[bits]

    @property
    def rights(self):
        # EAC Inspection System CHAT: b0 DG3, b1 DG4.
        value = self.authorization[-1] if self.authorization else 0
        return {"read_dg3": bool(value & 1), "read_dg4": bool(value & 2), "raw": self.authorization.hex().upper()}

    @classmethod
    def parse(cls, data):
        tag, outer, consumed = parse_tlv(data)
        if tag != "7F21" or consumed != len(data):
            raise CVCError("CVC must be exactly one 7F21 certificate object")
        fields = _children(outer)
        body, body_der = fields.get("7F4E", (None, None))
        signature = fields.get("5F37", (None,))[0]
        if body is None or signature is None:
            raise CVCError("CVC requires certificate body and signature")
        values = _children(body)
        required = ("5F29", "42", "5F20", "7F49", "7F4C", "5F25", "5F24")
        if any(name not in values for name in required) or values["5F29"][0] != b"\x00":
            raise CVCError("CVC body is missing mandatory profile fields")
        key = _children(values["7F49"][0])
        chat = _children(values["7F4C"][0])
        if "06" not in key or "06" not in chat or "53" not in chat:
            raise CVCError("CVC key/CHAT does not identify its algorithm and authorization")
        return cls(bytes(data), body_der, values["42"][0], values["5F20"][0],
                   _cvc_date(values["5F25"][0]), _cvc_date(values["5F24"][0]),
                   _decode_oid_bytes(key.pop("06")[0]), {name: x[0] for name, x in key.items()},
                   _decode_oid_bytes(chat["06"][0]), chat["53"][0], signature)


def parse_ef_cvca(data):
    """Return the current and optional previous CVCA certificate references."""
    refs, offset = [], 0
    while offset < len(data):
        tag, value, used = parse_tlv(data[offset:])
        if tag == "42":
            refs.append(value)
        offset += used
    if not 1 <= len(refs) <= 2:
        raise CVCError("EF.CVCA must contain one or two CA reference objects")
    return refs


_CVC_ALGORITHMS = {
    "0.4.0.127.0.7.2.2.2.1.1": ("RSA", SHA1, "v1.5"),
    "0.4.0.127.0.7.2.2.2.1.2": ("RSA", SHA256, "v1.5"),
    "0.4.0.127.0.7.2.2.2.1.3": ("RSA", SHA1, "PSS"),
    "0.4.0.127.0.7.2.2.2.1.4": ("RSA", SHA256, "PSS"),
    "0.4.0.127.0.7.2.2.2.1.5": ("RSA", SHA512, "v1.5"),
    "0.4.0.127.0.7.2.2.2.1.6": ("RSA", SHA512, "PSS"),
    "0.4.0.127.0.7.2.2.2.2.1": ("ECDSA", SHA1, "raw"),
    "0.4.0.127.0.7.2.2.2.2.2": ("ECDSA", SHA224, "raw"),
    "0.4.0.127.0.7.2.2.2.2.3": ("ECDSA", SHA256, "raw"),
    "0.4.0.127.0.7.2.2.2.2.4": ("ECDSA", SHA384, "raw"),
    "0.4.0.127.0.7.2.2.2.2.5": ("ECDSA", SHA512, "raw"),
}


def _key(cert, inherited=None):
    objects = cert.public_key_objects
    kind = _CVC_ALGORITHMS.get(cert.public_key_oid, (None,))[0]
    if kind == "RSA":
        return RSA.construct((int.from_bytes(objects["81"], "big"), int.from_bytes(objects["82"], "big")))
    inherited = inherited or {}
    merged = {**inherited, **objects}
    try:
        p, a, b, order = (int.from_bytes(merged[tag], "big") for tag in ("81", "82", "83", "85"))
        generator, public = merged["84"], objects["86"]
        cofactor = int.from_bytes(merged.get("87", b"\x01"), "big")
        curve = CurveFp(p, a, b, cofactor)
        width = (p.bit_length() + 7) // 8
        g = Point(curve, int.from_bytes(generator[1:1+width], "big"), int.from_bytes(generator[1+width:], "big"), order)
        domain = Curve("CVC explicit", curve, g, None)
        vk = VerifyingKey.from_string(public[1:], curve=domain)
        return vk, merged
    except Exception as exc:
        raise CVCError(f"Incomplete/invalid CVC EC key: {exc}") from exc


def _verify(child, parent, inherited=None):
    algorithm = _CVC_ALGORITHMS.get(parent.public_key_oid)
    if not algorithm:
        raise CVCError(f"Unsupported CVC signature algorithm {parent.public_key_oid}")
    public = _key(parent, inherited)
    hash_obj = algorithm[1].new(child.body_der)
    try:
        if algorithm[0] == "RSA":
            (pkcs1_15 if algorithm[2] == "v1.5" else pss).new(public).verify(hash_obj, child.signature)
            params = None
        else:
            vk, params = public
            vk.verify_digest(child.signature, hash_obj.digest(), sigdecode=sigdecode_string, allow_truncate=True)
        return params
    except (ValueError, TypeError, BadSignatureError) as exc:
        raise CVCError(f"CVC signature validation failed: {exc}") from exc


def validate_cvc_chain(certificates, trust_anchors, *, reference_date=None):
    """Build CVCA/link/DV/IS paths with CHAT, role, and date enforcement."""
    certs = [x if isinstance(x, CVCertificate) else CVCertificate.parse(x) for x in certificates]
    anchors = [x if isinstance(x, CVCertificate) else CVCertificate.parse(x) for x in trust_anchors]
    now = reference_date or date.today()
    chain = []
    current = certs[0] if certs else None
    while current:
        parents = [x for x in (*certs, *anchors) if x.chr == current.car and x not in chain and x is not current]
        if not parents:
            raise CVCError("CVC chain does not reach an explicit CVCA trust anchor")
        parent = parents[0]
        chain.append(current)
        if parent in anchors:
            chain.append(parent)
            break
        current = parent
    if not chain or chain[-1] not in anchors:
        raise CVCError("Empty CVC chain")
    inherited = None
    for index in range(len(chain) - 2, -1, -1):
        child, parent = chain[index], chain[index + 1]
        inherited = _verify(child, parent, inherited)
        valid_roles = {("IS", "DV-foreign"), ("IS", "DV-domestic"),
                       ("DV-foreign", "CVCA"), ("DV-domestic", "CVCA"), ("CVCA", "CVCA")}
        if (child.role, parent.role) not in valid_roles or child.chat_oid != parent.chat_oid:
            raise CVCError(f"Invalid CVC role/terminal-type transition {parent.role}->{child.role}")
        if not child.effective <= now <= child.expiration:
            raise CVCError(f"{child.role} certificate is outside its validity period")
        if int.from_bytes(child.authorization, "big") & ~int.from_bytes(parent.authorization, "big"):
            raise CVCError("Child CVC grants CHAT rights absent from its issuer")
    return chain


class TerminalAuthentication:
    def __init__(self, iso7816):
        self.iso7816 = iso7816

    def perform(self, terminal_chain, private_key_der, cvca_references, id_picc, *, ca_ephemeral_public_key=b""):
        chain = [x if isinstance(x, CVCertificate) else CVCertificate.parse(x) for x in terminal_chain]
        if not chain or chain[-1].car not in cvca_references:
            raise CVCError("Terminal chain does not target current/previous EF.CVCA reference")
        for cert in reversed(chain):
            self.iso7816.transmit(APDUCommand("00", "22", "81", "B6", data=_tlv("83", cert.car)), "TA MSE:Set DST")
            _, certificate_data, _ = parse_tlv(cert.encoded)
            self.iso7816.transmit_chained(
                APDUCommand("00", "2A", "00", "BE", data=certificate_data, le=256),
                source="terminal-authentication",
            )
        terminal = chain[0]
        self.iso7816.transmit(APDUCommand("00", "22", "C1", "A4", data=_tlv("83", terminal.chr)), "TA MSE:Set AT")
        challenge = self.iso7816.get_challenge()
        message = bytes(id_picc) + bytes(challenge)
        if ca_ephemeral_public_key:
            ca_key = bytes(ca_ephemeral_public_key)
            message += (ca_key[1:1 + (len(ca_key) - 1) // 2]
                        if ca_key[0] == 0x04 and len(ca_key) % 2 else hashlib.sha1(ca_key).digest())
        algorithm = _CVC_ALGORITHMS[terminal.public_key_oid]
        if algorithm[0] == "RSA":
            key = RSA.import_key(private_key_der)
            digest = algorithm[1].new(message)
            signature = (pkcs1_15 if algorithm[2] == "v1.5" else pss).new(key).sign(digest)
        else:
            key = SigningKey.from_der(private_key_der)
            signature = key.sign_digest(algorithm[1].new(message).digest(), sigencode=sigencode_string, allow_truncate=True)
        self.iso7816.transmit(APDUCommand("00", "82", "00", "00", data=signature), "TA External Authenticate")
        return {"terminal": terminal.chr.decode("ascii", "replace"), "rights": terminal.rights, "challenge": challenge.hex().upper()}
