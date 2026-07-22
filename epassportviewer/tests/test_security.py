import json
from types import SimpleNamespace

from pypassport.doc9303.security_info import PACEInfo

from epassportviewer.security import SecurityPane


class FakeEF(dict):
    def __init__(self, tag, **values):
        super().__init__(values)
        self.tag = tag
        self.file = bytes.fromhex(tag)


def _titles(report):
    return {finding.title for finding in report.findings}


def _pane_for(ep):
    pane = SecurityPane.__new__(SecurityPane)
    pane.parent = SimpleNamespace(ep=ep)
    pane._cached_checks_ep = None
    pane._cached_checks = {}
    pane._cached_integrity = {}
    pane._cached_atr = None
    pane._cached_uid = None
    pane._cached_acquisition_errors = {}
    pane._cached_access_control = None
    pane._cached_sm_type = "none"
    pane._cached_sod_verification = None
    pane._set_run_status = lambda _status: None
    pane._cached_files = lambda: {"SOD": FakeEF("77", dg_hashes={})}
    reports = []
    pane._render_report = lambda report, _files: reports.append(report)
    return pane, reports


def test_cached_refresh_keeps_signature_verification_result_for_current_passport():
    ep = SimpleNamespace(
        access_control=None,
        iso7816=SimpleNamespace(ciphering=None),
        sod_verification_info=None,
    )
    pane, reports = _pane_for(ep)

    assert pane.refresh_cached()
    assert "EF.SOD signature chain was not verified" in _titles(reports[-1])

    assert pane.refresh_cached(checks={"sod_signature_verified": True, "sod_signature_error": ""})
    assert "EF.SOD signature chain was not verified" not in _titles(reports[-1])

    assert pane.refresh_cached()
    assert "EF.SOD signature chain was not verified" not in _titles(reports[-1])

    pane.parent.ep = SimpleNamespace(
        access_control=None,
        iso7816=SimpleNamespace(ciphering=None),
        sod_verification_info=None,
    )
    assert pane.refresh_cached()
    assert "EF.SOD signature chain was not verified" in _titles(reports[-1])


def test_cached_refresh_keeps_integrity_and_live_details_for_current_passport():
    ep = SimpleNamespace(
        access_control=None,
        iso7816=SimpleNamespace(ciphering=None),
        sod_verification_info=None,
    )
    pane, reports = _pane_for(ep)
    pane._cached_files = lambda: {
        "SOD": FakeEF("77", dg_hashes={1: "AA"}),
        "DG1": FakeEF("61"),
    }

    assert pane.refresh_cached(
        integrity={"DG1": False},
        live_details={
            "atr": b"\x3b\x00",
            "uid": b"\x01\x02",
            "acquisition_errors": {"DG2": "Unreadable"},
        },
    )
    report = reports[-1]
    assert report.summary["atr"] == "3B00"
    assert report.summary["uid"] == "0102"
    assert report.acquisition_errors == {"DG2": "Unreadable"}
    assert "Data-group hash mismatch against EF.SOD" in _titles(report)

    assert pane.refresh_cached(checks={"sod_signature_verified": True})
    report = reports[-1]
    assert report.summary["atr"] == "3B00"
    assert report.summary["uid"] == "0102"
    assert report.acquisition_errors == {"DG2": "Unreadable"}
    assert "Data-group hash mismatch against EF.SOD" in _titles(report)


class _AesCipher:
    pass


def test_snapshot_metadata_restores_offline_capture_context():
    ep = SimpleNamespace(
        access_control=SimpleNamespace(
            mechanism="PACE",
            pace_info=PACEInfo("0.4.0.127.0.7.2.2.4.2.2", version=2, parameter_id=13),
        ),
        iso7816=SimpleNamespace(ciphering=_AesCipher()),
        sod_verification_info={"document_signer_certificate": {"serial_number": b"\x01"}},
    )
    pane, _reports = _pane_for(ep)
    pane._cached_files = lambda: {
        "SOD": FakeEF("77", dg_hashes={1: "AA"}),
        "DG1": FakeEF("61"),
    }

    assert pane.refresh_cached(
        checks={"sod_signature_verified": True},
        integrity={"DG1": True},
        live_details={
            "atr": b"\x3b\x00",
            "uid": b"\x01\x02",
            "acquisition_errors": {"DG2": "Unreadable"},
        },
    )
    payload = pane.get_snapshot_metadata()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["sod_verification"]["document_signer_certificate"]["serial_number"] == "01"

    offline, reports = _pane_for(None)
    offline._cached_files = pane._cached_files
    assert offline.load_snapshot_metadata(payload)

    report = reports[-1]
    assert report.summary["access_control"] == "PACE"
    assert report.summary["secure_messaging"] == "AES"
    assert report.summary["atr"] == "3B00"
    assert report.summary["uid"] == "0102"
    assert report.acquisition_errors == {"DG2": "Unreadable"}
    assert report.protocols["access_control"]["selected_pace_info"]["oid"] == "0.4.0.127.0.7.2.2.4.2.2"
    assert "EF.SOD signature chain was not verified" not in _titles(report)
