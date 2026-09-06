from types import SimpleNamespace

from pypassport.apdu_history import APDUHistory, APDUTransaction
from pypassport.conformance import ConformanceProfile, ConformanceRunner
from pypassport import conformance_cli


class _EF(dict):
    def __init__(self, name, errors=()):
        super().__init__(parse_errors=list(errors))
        self.file = name.encode()


class _FileSystem:
    def enumerate(self, application, extra_fids=()):
        return [SimpleNamespace(selected=True), SimpleNamespace(selected=False)]


class _Passport:
    def __init__(self):
        self.access_control = SimpleNamespace(mechanism="PACE", downgraded=False, pace_info=SimpleNamespace(oid="1.2.3"))
        self.file_system = _FileSystem()
        self.files = {"COM": _EF("COM"), "DG1": _EF("DG1"), "SOD": _EF("SOD")}

    def __getitem__(self, name):
        return self.files[name]

    @staticmethod
    def do_verify_dg_integrity(_files):
        return {"DG1": True}


def test_live_conformance_report_is_redacted_and_machine_readable():
    APDUHistory.get().clear()
    APDUHistory.get().record(
        APDUTransaction("00", "A4", "04", "0C", "07", "SECRET", "", "PRIVATE", 0x90, 0, True, "AES", "read")
    )
    passport = _Passport()
    report = ConformanceRunner(passport).run(
        ConformanceProfile(allowed_access_controls=("PACE",), allowed_pace_oids=("1.2.3",))
    ).to_dict()

    assert report["verdict"] == "PASS"
    assert {check["name"] for check in report["checks"]} >= {
        "access_control", "pace_profile", "file:COM", "file:DG1", "file:SOD", "filesystem", "data_group_integrity"
    }
    assert report["apdu_evidence"] == {
        "transaction_count": 0,
        "status_words": {},
        "authenticated_response_count": 0,
        "unauthenticated_response_count": 0,
    }
    assert "SECRET" not in str(report) and "PRIVATE" not in str(report)


def test_conformance_profile_reports_access_parse_and_integrity_failures():
    passport = _Passport()
    passport.access_control = SimpleNamespace(mechanism="BAC", downgraded=True, pace_info=None)
    passport.files["DG1"] = _EF("DG1", errors=("bad TLV",))
    passport.do_verify_dg_integrity = lambda _files: {"DG1": False}
    report = ConformanceRunner(passport).run(
        ConformanceProfile(allowed_access_controls=("PACE",), forbid_bac_downgrade=True)
    )

    assert report.verdict == "FAIL"
    failed = {check.name for check in report.checks if check.status == "fail"}
    assert failed >= {"access_control", "pace_downgrade", "file:DG1", "data_group_integrity"}


def test_conformance_cli_reads_credentials_from_environment_and_writes_only_redacted_evidence(monkeypatch, tmp_path):
    passports = []

    class FakePassport(_Passport):
        def __init__(self, connection, mrz, select_aid):
            super().__init__()
            passports.append((connection, mrz, select_aid))

        def open(self, **_kwargs):
            return self.access_control

    monkeypatch.setattr(conformance_cli, "EPassport", FakePassport)
    monkeypatch.setattr(conformance_cli.reader, "get_reader", lambda _selector: object())
    monkeypatch.setenv("EPASSPORT_MRZ", "CONFIDENTIAL-MRZ")
    output = tmp_path / "report.json"

    assert conformance_cli.main(["--access-control", "pace", "--report", str(output)]) == 0
    encoded = output.read_text()
    assert passports[0][1] == "CONFIDENTIAL-MRZ"
    assert "CONFIDENTIAL-MRZ" not in encoded
