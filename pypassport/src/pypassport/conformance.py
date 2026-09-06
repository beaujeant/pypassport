"""Repeatable, privacy-preserving interoperability checks for live eMRTDs.

The checks are aligned with the ISO 7816/LDS/PACE/EAC areas in BSI TR-03105.
They deliberately operate on an already-authenticated :class:`EPassport` so
credentials never become part of the report.  The result records outcomes and
APDU status histograms, but not document bytes, MRZ values, challenges, keys,
certificate holder references, or exact APDUs.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from pypassport.apdu_history import APDUHistory
from pypassport.doc9303.file_context import EMRTD


@dataclass(frozen=True)
class ConformanceProfile:
    """Issuer/lab expectations which can safely be stored in source control."""

    name: str = "ICAO baseline"
    required_files: tuple[str, ...] = ("COM", "DG1", "SOD")
    allowed_access_controls: tuple[str, ...] = ("PACE", "BAC")
    allowed_pace_oids: tuple[str, ...] = ()
    forbid_bac_downgrade: bool = False
    reject_parse_errors: bool = True
    verify_data_group_integrity: bool = True
    verify_sod_signature: bool = False
    verify_active_authentication: bool = False
    verify_chip_authentication: bool = False
    verify_terminal_authentication: bool = False
    chip_authentication_source: str = "DG14"
    chip_authentication_key_id: int | None = None
    enumerate_file_system: bool = True
    application: str = EMRTD
    extra_fids: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ConformanceProfile":
        """Construct a profile from JSON-safe lab configuration."""

        fields = {
            "name": str(value.get("name", "ICAO baseline")),
            "required_files": tuple(str(item) for item in value.get("required_files", cls.required_files)),
            "allowed_access_controls": tuple(
                str(item).upper() for item in value.get("allowed_access_controls", cls.allowed_access_controls)
            ),
            "allowed_pace_oids": tuple(str(item) for item in value.get("allowed_pace_oids", ())),
            "forbid_bac_downgrade": bool(value.get("forbid_bac_downgrade", False)),
            "reject_parse_errors": bool(value.get("reject_parse_errors", True)),
            "verify_data_group_integrity": bool(value.get("verify_data_group_integrity", True)),
            "verify_sod_signature": bool(value.get("verify_sod_signature", False)),
            "verify_active_authentication": bool(value.get("verify_active_authentication", False)),
            "verify_chip_authentication": bool(value.get("verify_chip_authentication", False)),
            "verify_terminal_authentication": bool(value.get("verify_terminal_authentication", False)),
            "chip_authentication_source": str(value.get("chip_authentication_source", "DG14")),
            "chip_authentication_key_id": value.get("chip_authentication_key_id"),
            "enumerate_file_system": bool(value.get("enumerate_file_system", True)),
            "application": str(value.get("application", EMRTD)),
            "extra_fids": tuple(str(item).upper() for item in value.get("extra_fids", ())),
        }
        return cls(**fields)


@dataclass(frozen=True)
class ConformanceCheck:
    name: str
    status: str
    expected: str
    observed: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConformanceReport:
    profile: str
    started_at: str
    finished_at: str
    verdict: str
    checks: tuple[ConformanceCheck, ...]
    apdu_evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "verdict": self.verdict,
            "checks": [asdict(check) for check in self.checks],
            "apdu_evidence": self.apdu_evidence,
            "redaction": "No credentials, document contents, cryptographic material, exact APDUs, ATR, or UID included.",
        }


class ConformanceRunner:
    """Run an interoperability profile against an open live session."""

    def __init__(self, passport):
        self.passport = passport
        self._checks: list[ConformanceCheck] = []

    def run(
        self,
        profile: ConformanceProfile,
        *,
        csca_directory: str | None = None,
        terminal_credentials: Mapping[str, Any] | None = None,
    ) -> ConformanceReport:
        started = datetime.now(timezone.utc).isoformat()
        first_apdu = len(APDUHistory.get())
        self._checks = []
        self._check_access_control(profile)
        captured = self._check_files(profile)
        if profile.enumerate_file_system:
            self._check_file_system(profile)
        if profile.verify_data_group_integrity:
            self._check_integrity(captured)
        if profile.verify_sod_signature:
            self._check_sod_signature(csca_directory)
        if profile.verify_active_authentication:
            self._check_active_authentication()
        if profile.verify_chip_authentication:
            self._check_chip_authentication(profile)
        if profile.verify_terminal_authentication:
            self._check_terminal_authentication(terminal_credentials)
        finished = datetime.now(timezone.utc).isoformat()
        failed = any(check.status == "fail" for check in self._checks)
        errored = any(check.status == "error" for check in self._checks)
        return ConformanceReport(
            profile.name,
            started,
            finished,
            "FAIL" if failed or errored else "PASS",
            tuple(self._checks),
            self._apdu_summary(first_apdu),
        )

    def _add(self, name: str, status: str, expected: str, observed: str, **evidence: Any) -> None:
        self._checks.append(ConformanceCheck(name, status, expected, observed, evidence))

    def _check_access_control(self, profile: ConformanceProfile) -> None:
        result = getattr(self.passport, "access_control", None)
        mechanism = str(getattr(result, "mechanism", "NONE")).upper()
        allowed = tuple(value.upper() for value in profile.allowed_access_controls)
        status = "pass" if mechanism in allowed else "fail"
        self._add("access_control", status, "/".join(allowed), mechanism)
        if profile.forbid_bac_downgrade:
            downgraded = mechanism == "BAC" and bool(getattr(result, "downgraded", False))
            self._add("pace_downgrade", "fail" if downgraded else "pass", "not downgraded", str(downgraded))
        pace_info = getattr(result, "pace_info", None)
        pace_evidence = {}
        if pace_info is not None:
            pace_evidence = {
                name: getattr(pace_info, name, None)
                for name in ("oid", "version", "parameter_id", "key_agreement", "mapping", "cipher", "key_size")
            }
        if pace_evidence:
            self._checks[-1] = ConformanceCheck(
                self._checks[-1].name,
                self._checks[-1].status,
                self._checks[-1].expected,
                self._checks[-1].observed,
                {"pace": pace_evidence},
            )
        if profile.allowed_pace_oids and mechanism == "PACE":
            oid = str(getattr(pace_info, "oid", ""))
            self._add(
                "pace_profile",
                "pass" if oid in profile.allowed_pace_oids else "fail",
                "configured OID",
                oid or "missing",
            )

    def _check_files(self, profile: ConformanceProfile) -> list[Any]:
        captured = []
        for name in profile.required_files:
            try:
                ef = self.passport[name]
                if ef is None:
                    self._add(f"file:{name}", "fail", "readable", "unavailable")
                    continue
                if name.upper().startswith("DG"):
                    captured.append(ef)
                errors = ef.get("parse_errors", []) if isinstance(ef, Mapping) else []
                status = "fail" if profile.reject_parse_errors and errors else "pass"
                self._add(
                    f"file:{name}",
                    status,
                    "readable and structurally valid" if profile.reject_parse_errors else "readable",
                    f"{len(bytes(ef.file))} bytes",
                    parse_error_count=len(errors),
                )
            except Exception as exc:
                self._add(f"file:{name}", "error", "readable", type(exc).__name__)
        return captured

    def _check_file_system(self, profile: ConformanceProfile) -> None:
        try:
            probes = self.passport.file_system.enumerate(profile.application, extra_fids=profile.extra_fids)
            selected = sum(probe.selected for probe in probes)
            self._add("filesystem", "pass", "enumeration completed", f"{selected}/{len(probes)} known files selected")
        except Exception as exc:
            self._add("filesystem", "error", "enumeration completed", type(exc).__name__)

    def _check_integrity(self, files: list[Any]) -> None:
        try:
            result = self.passport.do_verify_dg_integrity(files)
            if not isinstance(result, Mapping) or not result:
                self._add("data_group_integrity", "error", "verified", "no result")
                return
            failures = sorted(name for name, valid in result.items() if valid is False)
            self._add(
                "data_group_integrity",
                "fail" if failures else "pass",
                "all requested SOD hashes match",
                "mismatch" if failures else "matched",
                mismatched_files=failures,
            )
        except Exception as exc:
            self._add("data_group_integrity", "error", "verified", type(exc).__name__)

    def _check_sod_signature(self, directory: str | None) -> None:
        if not directory:
            self._add("passive_authentication", "error", "trusted CSCA directory", "not configured")
            return
        try:
            self.passport.csca_directory = directory
            verified = bool(self.passport.do_verify_sod_certificate())
            self._add("passive_authentication", "pass" if verified else "fail", "trusted", str(verified))
        except Exception as exc:
            self._add("passive_authentication", "error", "trusted", type(exc).__name__)

    def _check_active_authentication(self) -> None:
        try:
            verified = bool(self.passport.do_active_authentication())
            self._add("active_authentication", "pass" if verified else "fail", "valid chip proof", str(verified))
        except Exception as exc:
            self._add("active_authentication", "error", "valid chip proof", type(exc).__name__)

    def _check_chip_authentication(self, profile: ConformanceProfile) -> None:
        try:
            result = self.passport.do_chip_authentication(
                source=profile.chip_authentication_source,
                key_id=profile.chip_authentication_key_id,
            )
            self._add(
                "chip_authentication",
                "pass",
                "fresh keys confirmed by authenticated response",
                f"v{result.version} {result.key_agreement}/{result.cipher}-{result.key_size}",
            )
        except Exception as exc:
            self._add("chip_authentication", "error", "successful", type(exc).__name__)

    def _check_terminal_authentication(self, credentials: Mapping[str, Any] | None) -> None:
        if not credentials:
            self._add("terminal_authentication", "error", "explicit credentials", "not configured")
            return
        try:
            result = self.passport.do_terminal_authentication(**credentials)
            ungranted = [row for row in result.get("negative_rights", []) if row.get("enforced") is False]
            self._add(
                "terminal_authentication",
                "fail" if ungranted else "pass",
                "CVC path accepted and CHAT rights enforced",
                "authorization bypass" if ungranted else "authenticated",
                rights=result.get("rights", {}),
                negative_right_failures=[row.get("file", "unknown") for row in ungranted],
            )
        except Exception as exc:
            self._add("terminal_authentication", "error", "successful", type(exc).__name__)

    @staticmethod
    def _apdu_summary(first: int) -> dict[str, Any]:
        entries = list(APDUHistory.get())[first:]
        statuses = Counter(f"{entry.response_sw1:02X}{entry.response_sw2:02X}" for entry in entries)
        return {
            "transaction_count": len(entries),
            "status_words": dict(sorted(statuses.items())),
            "authenticated_response_count": sum(entry.response_authenticated is True for entry in entries),
            "unauthenticated_response_count": sum(entry.response_authenticated is False for entry in entries),
        }
