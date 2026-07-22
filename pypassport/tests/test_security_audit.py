import json
from types import SimpleNamespace

from pypassport.doc9303.security_info import PACEInfo
from pypassport.security_audit import build_security_report


class FakeEF(dict):
    def __init__(self, tag, **values):
        super().__init__(values)
        self.tag = tag
        self.file = bytes.fromhex(tag if len(tag) % 2 == 0 else "00")


def _titles(report):
    return {finding.title for finding in report.findings}


def test_report_flags_crypto_inventory_and_integrity_findings():
    files = {
        "CardAccess": FakeEF(
            "42",
            security_infos=[PACEInfo("0.4.0.127.0.7.2.2.4.2.1", version=2, parameter_id=13)],
        ),
        "COM": FakeEF("60", **{"5C": ["61", "6E", "6F"]}),
        "SOD": FakeEF(
            "77",
            dg_hashes={1: "AA", 14: "BB"},
            digest_algorithms=["sha1"],
            hash_algorithm="sha1",
            signer_infos=[{"signature_algorithm": "sha1WithRSAEncryption"}],
        ),
        "DG1": FakeEF("61"),
        "DG14": FakeEF(
            "6E",
            security_infos=[{"protocol": "id-CA-ECDH-3DES-CBC-CBC", "protocol_oid": "0.4.0.127.0.7.2.2.3.2.1"}],
        ),
        "DG15": FakeEF("6F", algorithm="rsaEncryption", modulus_bits=1024),
    }
    access = SimpleNamespace(
        mechanism="BAC",
        pace_info=PACEInfo("0.4.0.127.0.7.2.2.4.2.1", version=2, parameter_id=13),
    )

    report = build_security_report(files, access_control=access, integrity={"DG1": False})

    assert "PACE is limited to 3DES variants" in _titles(report)
    assert "Session negotiated BAC while PACE is advertised" in _titles(report)
    assert "DG15 RSA key is below 2048 bits" in _titles(report)
    assert "Chip Authentication is limited to 3DES" in _titles(report)
    assert "Data-group hash mismatch against EF.SOD" in _titles(report)
    assert "EF.SOD does not cover every EF.COM data group" in _titles(report)
    assert "EF.SOD uses legacy digest or signature algorithms" in _titles(report)


def test_report_preserves_parser_anomalies_and_serialises():
    dg2 = FakeEF(
        "75",
        parse_errors=[{"context": "biometric_templates", "message": "declared 2, parsed 1", "raw_hex": b"\x01\x02"}],
        actual_outer_tag="63",
        expected_outer_tag="75",
    )

    report = build_security_report({"DG2": dg2}, atr=b"\x3B\x00", uid=b"\x01\x02")
    payload = json.loads(report.to_json())

    assert report.summary["atr"] == "3B00"
    assert report.summary["uid"] == "0102"
    assert report.summary["parser_anomaly_count"] == 1
    assert "DG2 outer tag does not match its EF identity" in _titles(report)
    assert "DG2 contains parser anomalies" in _titles(report)
    assert payload["files"][0]["parse_errors"][0]["raw_hex"] == "0102"
