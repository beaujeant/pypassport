"""Security posture reporting for ICAO 9303 eMRTD captures.

The GUI needs a compact, exportable view of a document's security posture
without re-implementing protocol knowledge in Tk widgets.  This module takes
already-read elementary files plus optional live-check results and turns them
into a stable report:

* protocol inventory (PACE, AA, CA, TA, SOD algorithms),
* file inventory and parser anomalies,
* analyst-facing findings with evidence and remediation guidance.

The report builder is deliberately side-effect free.  It never talks to a
card and it never assumes a missing file is proof of a document defect: a file
may simply not have been captured yet.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, cast

from pypassport.doc9303 import converter
from pypassport.doc9303.security_info import PACEInfo

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_FILE_ORDER = (
    "CardAccess",
    "CardSecurity",
    "COM",
    "SOD",
    "DG1",
    "DG2",
    "DG3",
    "DG4",
    "DG5",
    "DG6",
    "DG7",
    "DG8",
    "DG9",
    "DG10",
    "DG11",
    "DG12",
    "DG13",
    "DG14",
    "DG15",
    "DG16",
)


@dataclass(frozen=True)
class SecurityFinding:
    """One analyst-facing observation about a captured document."""

    severity: str
    category: str
    title: str
    evidence: str
    recommendation: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class SecurityReport:
    """Exportable result of :func:`build_security_report`."""

    generated_at: str
    summary: dict[str, Any]
    protocols: dict[str, Any]
    files: list[dict[str, Any]]
    findings: list[SecurityFinding] = field(default_factory=list)
    acquisition_errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "summary": _json_value(self.summary),
            "protocols": _json_value(self.protocols),
            "files": _json_value(self.files),
            "findings": [finding.to_dict() for finding in self.findings],
            "acquisition_errors": dict(self.acquisition_errors),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def build_security_report(
    files: Mapping[str, Any],
    *,
    access_control: Any = None,
    atr: bytes | str | None = None,
    uid: bytes | str | None = None,
    sm_type: str = "",
    integrity: Mapping[str, bool | None] | None = None,
    sod_verification: Mapping[str, Any] | None = None,
    checks: Mapping[str, Any] | None = None,
    acquisition_errors: Mapping[str, str] | None = None,
) -> SecurityReport:
    """Build a report from parsed elementary files and optional live results.

    ``files`` is keyed by logical names such as ``"COM"``, ``"SOD"``,
    ``"DG14"`` and ``"DG15"``.  Values may be real ``ElementaryFile``
    instances or test doubles exposing the same dict-like fields.
    """

    captured = {name: value for name, value in files.items() if value is not None}
    checks = dict(checks or {})
    integrity = dict(integrity or {})
    acquisition_errors = dict(acquisition_errors or {})

    file_rows = [_file_row(name, captured[name], integrity) for name in _ordered_names(captured)]
    advertised_dgs = _advertised_dgs(captured.get("COM"))
    captured_dgs = sorted((name for name in captured if name.startswith("DG")), key=_dg_sort_key)
    sod_hashed_dgs = _sod_hashed_dgs(captured.get("SOD"))
    pace_infos = _pace_infos(captured.get("CardAccess"), access_control)
    dg14_infos = _security_infos(captured.get("DG14"))
    card_security_infos = _security_infos(captured.get("CardSecurity"))
    for info in card_security_infos:
        info["source"] = "authenticated EF.CardSecurity"

    protocols: dict[str, Any] = {
        "access_control": _access_control_summary(access_control, sm_type),
        "pace": pace_infos,
        "active_authentication": _active_authentication_summary(captured.get("DG15"), dg14_infos, checks),
        "chip_authentication": [info for info in dg14_infos + card_security_infos if _protocol_startswith(info, "id-CA-")],
        "terminal_authentication": [info for info in dg14_infos + card_security_infos if _protocol_startswith(info, "id-TA")],
        "extended_access_control_checks": {
            "chip_authentication": checks.get("chip_authentication"),
            "terminal_authentication": checks.get("terminal_authentication"),
            "terminal_rights": _json_value(checks.get("terminal_authentication_rights", {})),
            "negative_rights": _json_value(checks.get("terminal_negative_rights", [])),
        },
        "security_infos": dg14_infos + card_security_infos,
        "passive_authentication": _passive_authentication_summary(captured.get("SOD"), sod_verification, checks),
    }
    summary = {
        "atr": _hex_or_text(atr),
        "uid": _hex_or_text(uid),
        "access_control": protocols["access_control"].get("mechanism", "unknown"),
        "secure_messaging": protocols["access_control"].get("secure_messaging", "none"),
        "advertised_data_groups": advertised_dgs,
        "captured_data_groups": captured_dgs,
        "sod_hashed_data_groups": sod_hashed_dgs,
        "captured_file_count": len(captured),
        "parser_anomaly_count": sum(len(row["parse_errors"]) for row in file_rows),
    }

    findings: list[SecurityFinding] = []
    _add_parser_findings(findings, file_rows)
    _add_inventory_findings(findings, advertised_dgs, captured_dgs, sod_hashed_dgs, integrity)
    _add_access_control_findings(findings, pace_infos, access_control)
    _add_authentication_findings(findings, protocols, captured.get("DG15"), checks)
    _add_sod_findings(findings, captured.get("SOD"), protocols["passive_authentication"], sod_verification, checks)
    findings.sort(key=lambda item: (_SEVERITY_ORDER.get(item.severity, 99), item.category, item.title))

    return SecurityReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        protocols=protocols,
        files=file_rows,
        findings=findings,
        acquisition_errors=acquisition_errors,
    )


def _ordered_names(files: Mapping[str, Any]) -> list[str]:
    known = [name for name in _FILE_ORDER if name in files]
    extra = sorted(name for name in files if name not in _FILE_ORDER)
    return known + extra


def _dg_sort_key(name: str) -> tuple[int, str]:
    digits = "".join(ch for ch in name if ch.isdigit())
    return (int(digits) if digits else 999, name)


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex().upper()
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if is_dataclass(value):
        return _json_value(asdict(cast(Any, value)))
    return value


def _hex_or_text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.hex().upper()
    return value or ""


def _file_row(name: str, ef: Any, integrity: Mapping[str, bool | None]) -> dict[str, Any]:
    parse_errors = []
    if isinstance(ef, Mapping):
        raw_errors = ef.get("parse_errors", [])
        if isinstance(raw_errors, list):
            parse_errors = [_json_value(error) for error in raw_errors]
    try:
        length = len(ef.file)
    except Exception:
        length = None
    row = {
        "name": name,
        "tag": getattr(ef, "tag", ""),
        "length": length,
        "parse_errors": parse_errors,
        "outer_tag_mismatch": bool(isinstance(ef, Mapping) and ef.get("actual_outer_tag")),
        "integrity": integrity.get(name),
    }
    if isinstance(ef, Mapping):
        if ef.get("actual_outer_tag"):
            row["actual_outer_tag"] = ef["actual_outer_tag"]
            row["expected_outer_tag"] = ef.get("expected_outer_tag", getattr(ef, "tag", ""))
        if ef.get("_unparsed_tail"):
            row["unparsed_tail_hex"] = _json_value(ef["_unparsed_tail"])
    return row


def _advertised_dgs(com: Any) -> list[str]:
    if not isinstance(com, Mapping):
        return []
    tags = com.get("5C", [])
    if not isinstance(tags, list):
        return []
    names = []
    for tag in tags:
        try:
            name = converter.to_dg(tag)
        except KeyError:
            name = str(tag)
        if name not in names:
            names.append(name)
    return sorted(names, key=_dg_sort_key)


def _sod_hashed_dgs(sod: Any) -> list[str]:
    if not isinstance(sod, Mapping):
        return []
    hashes = sod.get("dg_hashes", {})
    if not isinstance(hashes, Mapping):
        return []
    names = []
    for key in hashes:
        try:
            names.append(f"DG{int(key)}")
        except (TypeError, ValueError):
            continue
    return sorted(names, key=_dg_sort_key)


def _pace_info_dict(info: Any) -> dict[str, Any]:
    if isinstance(info, PACEInfo):
        return {
            "oid": info.oid,
            "version": info.version,
            "parameter_id": info.parameter_id,
            "key_agreement": info.key_agreement,
            "mapping": info.mapping,
            "cipher": info.cipher,
            "key_size": info.key_size,
            "known": info.is_known(),
            "supported": info.is_supported(),
        }
    if isinstance(info, Mapping):
        return cast(dict[str, Any], _json_value(dict(info)))
    return {"value": str(info)}


def _pace_infos(card_access: Any, access_control: Any) -> list[dict[str, Any]]:
    infos: list[Any] = []
    if isinstance(card_access, Mapping):
        raw = card_access.get("security_infos", [])
        if isinstance(raw, list):
            infos.extend(raw)
    selected = getattr(access_control, "pace_info", None)
    if selected is not None and selected not in infos:
        infos.append(selected)
    return [_pace_info_dict(info) for info in infos]


def _security_infos(dg14: Any) -> list[dict[str, Any]]:
    if not isinstance(dg14, Mapping):
        return []
    infos = dg14.get("security_infos", [])
    if not isinstance(infos, list):
        return []
    return [_json_value(info) if isinstance(info, Mapping) else {"value": str(info)} for info in infos]


def _protocol_startswith(info: Mapping[str, Any], prefix: str) -> bool:
    return str(info.get("protocol", "")).startswith(prefix)


def _access_control_summary(access_control: Any, sm_type: str) -> dict[str, Any]:
    mechanism = getattr(access_control, "mechanism", None) or "unknown"
    summary = {
        "mechanism": mechanism,
        "secure_messaging": sm_type or ("none" if mechanism in ("NONE", "unknown") else "active"),
    }
    pace_info = getattr(access_control, "pace_info", None)
    if pace_info is not None:
        summary["selected_pace_info"] = _pace_info_dict(pace_info)
    advertised = getattr(access_control, "advertised_pace_infos", None)
    if advertised:
        summary["advertised_pace_infos"] = [_pace_info_dict(info) for info in advertised]
    attempts = getattr(access_control, "attempts", None)
    if attempts:
        summary["attempts"] = _json_value(attempts)
    fallback_reason = getattr(access_control, "fallback_reason", None)
    if fallback_reason:
        summary["fallback_reason"] = str(fallback_reason)
        summary["downgraded"] = bool(getattr(access_control, "downgraded", True))
    cam_result = getattr(access_control, "cam_result", None)
    if cam_result:
        summary["pace_cam"] = _json_value(cam_result)
    return summary


def _active_authentication_summary(dg15: Any, dg14_infos: list[dict[str, Any]], checks: Mapping[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "dg15_present": dg15 is not None,
        "live_check": checks.get("active_authentication"),
        "security_infos": [info for info in dg14_infos if _protocol_startswith(info, "id-icao-mrtd-security-aa")],
    }
    if isinstance(dg15, Mapping):
        for key in ("algorithm", "algorithm_oid", "key_length_bits", "modulus_bits", "public_exponent", "curve"):
            if key in dg15:
                summary[key] = _json_value(dg15[key])
    return summary


def _passive_authentication_summary(
    sod: Any,
    sod_verification: Mapping[str, Any] | None,
    checks: Mapping[str, Any],
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "sod_present": sod is not None,
        "signature_verified": checks.get("sod_signature_verified"),
        "signature_verification_error": checks.get("sod_signature_error", ""),
    }
    if isinstance(sod, Mapping):
        for key in (
            "content_type_oid",
            "digest_algorithms",
            "hash_algorithm",
            "hash_algorithm_oid",
            "signer_infos",
            "certificates",
        ):
            if key in sod:
                summary[key] = _json_value(sod[key])
    if sod_verification is not None:
        summary["verification_info"] = _json_value(dict(sod_verification))
    return summary


def _add(findings: list[SecurityFinding], severity: str, category: str, title: str, evidence: str, recommendation: str = ""):
    candidate = SecurityFinding(severity, category, title, evidence, recommendation)
    if candidate not in findings:
        findings.append(candidate)


def _add_parser_findings(findings: list[SecurityFinding], file_rows: list[dict[str, Any]]) -> None:
    for row in file_rows:
        name = row["name"]
        if row["outer_tag_mismatch"]:
            _add(
                findings,
                "medium",
                "structure",
                f"{name} outer tag does not match its EF identity",
                f"Expected {row.get('expected_outer_tag')}, received {row.get('actual_outer_tag')}.",
                "Keep the raw file in the case record and compare it against the issuer profile.",
            )
        if row["parse_errors"]:
            contexts = ", ".join(str(error.get("context", "unknown")) for error in row["parse_errors"])
            _add(
                findings,
                "low",
                "structure",
                f"{name} contains parser anomalies",
                f"{len(row['parse_errors'])} anomaly record(s): {contexts}.",
                "Review the raw TLV/DER bytes before treating parsed fields as authoritative.",
            )


def _add_inventory_findings(
    findings: list[SecurityFinding],
    advertised_dgs: list[str],
    captured_dgs: list[str],
    sod_hashed_dgs: list[str],
    integrity: Mapping[str, bool | None],
) -> None:
    missing_capture = [name for name in advertised_dgs if name not in captured_dgs]
    if missing_capture:
        _add(
            findings,
            "info",
            "coverage",
            "EF.COM advertises data groups that were not captured",
            ", ".join(missing_capture),
            "Re-read these EFs and inspect the returned status words in Traffic.",
        )
    undeclared = [name for name in captured_dgs if advertised_dgs and name not in advertised_dgs]
    if undeclared:
        _add(
            findings,
            "medium",
            "structure",
            "Readable data groups are not declared in EF.COM",
            ", ".join(undeclared),
            "Confirm whether the issuer intentionally exposes undeclared LDS files.",
        )
    unhashed = [name for name in advertised_dgs if sod_hashed_dgs and name not in sod_hashed_dgs]
    if unhashed:
        _add(
            findings,
            "medium",
            "integrity",
            "EF.SOD does not cover every EF.COM data group",
            ", ".join(unhashed),
            "Treat uncovered LDS content as unauthenticated until issuer evidence explains it.",
        )
    mismatches = sorted((name for name, result in integrity.items() if result is False), key=_dg_sort_key)
    if mismatches:
        _add(
            findings,
            "high",
            "integrity",
            "Data-group hash mismatch against EF.SOD",
            ", ".join(mismatches),
            "Preserve the capture and investigate tampering, corruption, or parser boundary errors.",
        )


def _add_access_control_findings(findings: list[SecurityFinding], pace_infos: list[dict[str, Any]], access_control: Any) -> None:
    if not pace_infos:
        _add(
            findings,
            "medium",
            "access-control",
            "No PACEInfo was captured",
            "The capture does not show EF.CardAccess advertising PACE.",
            "Confirm whether the document is BAC-only or whether EF.CardAccess was unreadable.",
        )
        return

    weak = [info for info in pace_infos if str(info.get("cipher", "")).upper() == "3DES"]
    strong = [info for info in pace_infos if str(info.get("cipher", "")).upper() == "AES"]
    if weak and not strong:
        _add(
            findings,
            "medium",
            "access-control",
            "PACE is limited to 3DES variants",
            ", ".join(str(info.get("oid", "")) for info in weak),
            "Prefer AES-based PACE profiles for new issuances.",
        )
    elif weak:
        _add(
            findings,
            "info",
            "access-control",
            "Legacy 3DES PACE variants are also advertised",
            ", ".join(str(info.get("oid", "")) for info in weak),
            "Check whether inspection systems can be constrained to AES variants.",
        )

    if getattr(access_control, "mechanism", "") == "BAC":
        _add(
            findings,
            "low",
            "access-control",
            "Session negotiated BAC while PACE is advertised",
            "PACEInfo is present, but the captured live session used BAC.",
            "Review whether this was an intentional fallback or a downgrade condition.",
        )
    fallback_reason = getattr(access_control, "fallback_reason", None)
    if fallback_reason and fallback_reason != "cardaccess_missing":
        _add(
            findings,
            "high",
            "access-control",
            "PACE failure or discovery error caused BAC fallback",
            str(fallback_reason),
            "Repeat PACE and forced-BAC tests separately; do not accept the session as equivalent to PACE.",
        )
    cam_result = getattr(access_control, "cam_result", None)
    if isinstance(cam_result, Mapping) and cam_result.get("passive_authentication") == "pending":
        _add(
            findings,
            "high",
            "anti-cloning",
            "PACE-CAM proof is not yet anchored",
            "Encrypted CA data matched EF.CardSecurity, but its Document Signer chain has not completed Passive Authentication.",
            "Validate the signed Master List/CSCA path and EF.CardSecurity signer before treating the chip as genuine.",
        )


def _add_authentication_findings(
    findings: list[SecurityFinding],
    protocols: Mapping[str, Any],
    dg15: Any,
    checks: Mapping[str, Any],
) -> None:
    ca = protocols["chip_authentication"]
    if dg15 is None and not ca:
        _add(
            findings,
            "medium",
            "anti-cloning",
            "No anti-cloning mechanism was observed",
            "DG15 is absent and DG14 did not expose Chip Authentication.",
            "Confirm whether the issuer relies on an unobserved CA profile or accepts clone risk.",
        )
    elif dg15 is None:
        _add(
            findings,
            "info",
            "anti-cloning",
            "Active Authentication key not captured",
            "DG15 is absent; Chip Authentication information is present in DG14.",
        )
    elif not ca:
        _add(
            findings,
            "info",
            "anti-cloning",
            "Chip Authentication not observed",
            "DG15 supports Active Authentication, but DG14 contains no CA entry.",
        )

    if isinstance(dg15, Mapping):
        modulus_bits = dg15.get("modulus_bits")
        if isinstance(modulus_bits, int) and modulus_bits < 2048:
            severity = "high" if modulus_bits < 1024 else "medium"
            _add(
                findings,
                severity,
                "crypto",
                "DG15 RSA key is below 2048 bits",
                f"RSA modulus length: {modulus_bits} bits.",
                "Use current issuer cryptographic profiles for future document generations.",
            )
        algorithm = str(dg15.get("algorithm", ""))
        if algorithm.lower() == "dsa":
            _add(
                findings,
                "medium",
                "crypto",
                "DG15 uses DSA",
                "SubjectPublicKeyInfo algorithm is DSA.",
                "Prefer current RSA or ECDSA profiles for new issuances.",
            )

    ca_3des = [info for info in ca if "3DES" in str(info.get("protocol", "")).upper()]
    ca_aes = [info for info in ca if "AES" in str(info.get("protocol", "")).upper()]
    if ca_3des and not ca_aes:
        _add(
            findings,
            "medium",
            "crypto",
            "Chip Authentication is limited to 3DES",
            ", ".join(str(info.get("protocol", "")) for info in ca_3des),
            "Prefer AES-based Chip Authentication profiles for new issuances.",
        )

    if checks.get("active_authentication") is False:
        _add(
            findings,
            "high",
            "anti-cloning",
            "Active Authentication failed",
            "The live challenge response did not verify against DG15.",
            "Preserve the transaction trace and investigate a clone, corruption, or implementation defect.",
        )
    elif dg15 is not None and checks.get("active_authentication") is None and checks.get("active_authentication_error"):
        _add(
            findings,
            "info",
            "coverage",
            "Active Authentication result is inconclusive",
            str(checks["active_authentication_error"]),
            "Add the advertised signature profile to the verifier, then repeat one bounded challenge.",
        )
    if checks.get("chip_authentication") is False:
        _add(
            findings, "high", "anti-cloning", "Chip Authentication failed",
            str(checks.get("chip_authentication_error", "CA implicit authentication did not validate.")),
            "Preserve the key-selection and first fresh-SM exchanges.",
        )
    elif ca and checks.get("chip_authentication") is None:
        _add(
            findings,
            "info",
            "coverage",
            "Chip Authentication was advertised but not tested",
            str(
                checks.get(
                    "chip_authentication_error",
                    "DG14/EF.CardSecurity contains a CA protocol and public key, but no successful live CA result is attached.",
                )
            ),
            "Authenticate the key source, run CA, and require an authenticated response under the fresh keys.",
        )
    terminal = protocols["terminal_authentication"]
    if terminal and checks.get("terminal_authentication") is None:
        _add(
            findings,
            "info",
            "coverage",
            "Terminal Authentication was advertised but not tested",
            "DG14/EF.CardSecurity contains Terminal Authentication metadata without a live CVC/CHAT result.",
            "Run TA with an explicit CVCA trust anchor and test ungranted DG3/DG4 rights.",
        )
    negative = checks.get("terminal_negative_rights", [])
    if isinstance(negative, list):
        for probe in negative:
            if isinstance(probe, Mapping) and probe.get("enforced") is False:
                _add(findings, "high", "authorization", "Terminal CHAT restriction not enforced",
                     str(probe.get("security_issue", probe)),
                     "Retest with a minimal IS certificate and notify the document-application implementer.")


def _add_sod_findings(
    findings: list[SecurityFinding],
    sod: Any,
    passive: Mapping[str, Any],
    sod_verification: Mapping[str, Any] | None,
    checks: Mapping[str, Any],
) -> None:
    if sod is None:
        _add(
            findings,
            "info",
            "coverage",
            "EF.SOD was not captured",
            "Passive Authentication cannot be assessed from this report.",
            "Read EF.SOD and configure a CSCA directory before closing the assessment.",
        )
        return

    algorithms: list[str] = []
    if isinstance(sod, Mapping):
        algorithms.extend(str(item) for item in sod.get("digest_algorithms", []) if item)
        if sod.get("hash_algorithm"):
            algorithms.append(str(sod["hash_algorithm"]))
        for signer in sod.get("signer_infos", []) if isinstance(sod.get("signer_infos", []), list) else []:
            if isinstance(signer, Mapping) and signer.get("signature_algorithm"):
                algorithms.append(str(signer["signature_algorithm"]))
    weak = [algorithm for algorithm in algorithms if "sha1" in algorithm.lower() or "md5" in algorithm.lower()]
    if weak:
        severity = "high" if any("md5" in algorithm.lower() for algorithm in weak) else "low"
        _add(
            findings,
            severity,
            "crypto",
            "EF.SOD uses legacy digest or signature algorithms",
            ", ".join(sorted(set(weak))),
            "Compare against the issuer's current PKI profile and migration plan.",
        )

    if checks.get("sod_signature_verified") is False:
        _add(
            findings,
            "high",
            "integrity",
            "EF.SOD signature or certificate chain verification failed",
            str(checks.get("sod_signature_error", "Verification failed.")),
            "Preserve the SOD, DSC, CSCA set, and transaction trace for issuer review.",
        )
    elif checks.get("sod_signature_verified") is None and sod_verification is None:
        _add(
            findings,
            "info",
            "coverage",
            "EF.SOD signature chain was not verified",
            "No successful DSC-to-CSCA verification result is attached to this report.",
            "Configure the issuing state's CSCA certificates and run signature verification.",
        )

    if passive.get("signature_verification_error"):
        _add(
            findings,
            "info",
            "coverage",
            "Passive Authentication verification produced an error",
            str(passive["signature_verification_error"]),
        )
