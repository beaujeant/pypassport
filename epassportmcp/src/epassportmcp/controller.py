"""Stateful ePassport research controller used by the MCP entry point."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, cast

from pypassport import reader
from pypassport.apdu_history import APDUHistory
from pypassport.attacks.active_authentication_traceability import AATraceability
from pypassport.attacks.brute_force import BruteForce
from pypassport.attacks.mac_traceability import MacTraceability
from pypassport.attacks.sign_everything import SignEverything
from pypassport.conformance import ConformanceProfile, ConformanceRunner
from pypassport.doc9303 import converter, data_group
from pypassport.doc9303.access_control import NegotiationResult
from pypassport.doc9303.file_context import EMRTD, FILES, MF, FileReference, resolve_file
from pypassport.doc9303.mrz import MRZ
from pypassport.epassport import EPassport
from pypassport.fuzzing import (
    DEFAULT_STRATEGIES,
    SAFE_INS,
    STRATEGY_LABELS,
    generate_fuzz_cases,
    run_fuzz_campaign,
    summarize_fuzz_results,
)
from pypassport.iso7816 import ISO7816, APDUCommand, APDUResponse, ISO7816Exception
from pypassport.security_audit import build_security_report
from pypassport.utils import to_hex_string

from .catalog import ACTION_SPECS, GROUPS
from .schema_validation import validate


class ActionError(RuntimeError):
    """A caller-correctable action error returned as structured MCP output."""

    def __init__(self, code: str, message: str, *, details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details


class PassportController:
    """Serialize operations on one viewer-owned reader and research case.

    PC/SC connections and Secure Messaging state are sequential resources.
    MCP clients may issue concurrent requests, so every action is serialized by
    this controller's re-entrant lock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.connection: Any = None
        self.iso7816: ISO7816 | None = None
        self.passport: EPassport | None = None
        self.reader_name = ""
        self._mrz: MRZ | None = None
        self._can: str | None = None
        self._access_mode = "auto"
        self._access_control: NegotiationResult | None = None
        self._offline_files: dict[str, Any] = {}
        self._checks: dict[str, Any] = {}
        self._integrity: dict[str, bool | None] = {}
        self._sod_verification: dict[str, Any] | None = None
        self._acquisition_errors: dict[str, str] = {}
        self._acquisition_evidence: dict[str, dict[str, Any]] = {}
        self._last_fuzz_results: list[Any] = []
        self._viewer_bound = False

    def bind_to_viewer(self) -> None:
        """Forbid direct reader replacement when hosted inside the GUI."""

        self._viewer_bound = True

    # ----------------------------- public front door -----------------------------

    def list_actions(self, *, group: str = "", query: str = "", detail: bool = False) -> dict[str, Any]:
        """Return a compact action index or selected lazy schemas."""

        group = group.strip().lower()
        query = query.strip().lower()
        if group and group not in GROUPS:
            raise ActionError("unknown_group", f"Unknown group {group!r}", details={"groups": GROUPS})
        matches = [
            spec
            for spec in ACTION_SPECS.values()
            if (not group or spec.group == group)
            and (
                not query
                or query in spec.name.lower()
                or query in spec.summary.lower()
                or query in spec.description.lower()
            )
        ]
        if not group and not query and not detail:
            return {
                "groups": [
                    {
                        "name": name,
                        "count": sum(1 for spec in ACTION_SPECS.values() if spec.group == name),
                    }
                    for name in GROUPS
                ],
                "total_actions": len(ACTION_SPECS),
                "next": "Call epassport_list_tools with group/query, or epassport_recommend_tools with your goal.",
            }
        return {"actions": [spec.detailed() if detail else spec.compact() for spec in matches]}

    def action_detail(self, action: str) -> dict[str, Any]:
        spec = ACTION_SPECS.get(action)
        if spec is None:
            raise ActionError("unknown_action", f"Unknown action {action!r}", details=self._similar_actions(action))
        return spec.detailed()

    def recommend(self, goal: str, *, max_actions: int = 8) -> dict[str, Any]:
        """Recommend only the action schemas needed for a stated analysis goal."""

        words = set(goal.lower().replace("/", " ").replace("-", " ").split())
        if words & {"dg3", "dg4", "protected", "bypass", "matrix", "without", "plaintext"}:
            recipe = [
                "reader.list", "session.connect", "session.authenticate", "passport.capture",
                "security.access_matrix", "security.chip_authentication", "security.discover_files",
                "security.aa_analysis",
            ]
            rationale = (
                "Measure the same object through isolated access states before interpreting an error as a biometric "
                "bypass."
            )
        elif words & {"fuzz", "fuzzing", "mutation", "mutate"}:
            recipe = [
                "reader.list",
                "session.connect",
                "session.authenticate",
                "fuzz.run",
                "fuzz.results",
                "session.reset",
            ]
            rationale = (
                "Bound mutations, save complete results in the MCP, inspect anomalies, and recover the card channel."
            )
        elif words & {"apdu", "raw", "wire", "low-level", "lowlevel", "plaintext"}:
            recipe = [
                "reader.list",
                "session.connect",
                "session.reset",
                "apdu.transmit",
                "apdu.history",
                "session.authenticate",
            ]
            rationale = (
                "Begin from a known reset state, preserve exact wire responses, "
                "then establish or recover Secure Messaging."
            )
        elif words & {"filesystem", "files", "fid", "sfi", "application", "aid"}:
            recipe = [
                "reader.list",
                "session.connect",
                "session.authenticate",
                "passport.filesystem",
                "security.discover_files",
                "passport.read_file",
                "apdu.history",
            ]
            rationale = "Discover every advertised application and preserve its FID/SFI context while probing files."
        elif words & {"eac", "chip", "terminal", "cvc", "biometric", "fingerprint", "iris"}:
            recipe = [
                "reader.list",
                "session.connect",
                "session.authenticate",
                "passport.capture",
                "security.chip_authentication",
                "security.terminal_authentication",
                "passport.read_file",
            ]
            rationale = "Authenticate DG14/CardSecurity, re-key with CA, validate the CVC path, then test CHAT rights."
        elif words & {"conformance", "interop", "interoperability", "compatibility", "issuer", "profile"}:
            recipe = [
                "reader.list",
                "session.connect",
                "session.authenticate",
                "security.conformance",
                "apdu.history",
            ]
            rationale = "Run the privacy-preserving profile and inspect only the status evidence behind failed checks."
        elif words & {"pace", "bac", "authentication", "encryption", "secure", "messaging"}:
            recipe = [
                "reader.list",
                "session.connect",
                "passport.read_file",
                "session.authenticate",
                "apdu.history",
                "session.reset",
            ]
            rationale = (
                "Inspect CardAccess, run an explicit or automatic access-control flow, "
                "and retain both clear and protected evidence."
            )
        elif words & {"traceability", "tracking", "oracle", "signing", "bruteforce", "brute"}:
            recipe = [
                "reader.list",
                "session.connect",
                "attack.aa_before_access",
                "attack.mac_traceability",
                "attack.sign_challenge",
                "attack.aa_traceability",
                "attack.aa_compare",
                "attack.bac_bruteforce",
            ]
            rationale = "Select the relevant implemented research attack, then re-authenticate before normal reads."
        elif words & {"offline", "snapshot", "capture", "import", "export"}:
            recipe = [
                "case.import_snapshot",
                "passport.inventory",
                "passport.read_file",
                "security.audit",
                "case.export_snapshot",
            ]
            rationale = "Load a bounded evidence case, inspect selected files, build findings, and preserve the result."
        else:
            recipe = [
                "reader.list",
                "session.connect",
                "session.authenticate",
                "passport.capture",
                "passport.verify",
                "security.audit",
                "apdu.history",
            ]
            rationale = (
                "Complete live acquisition and authenticity checks, then inspect findings and their wire evidence."
            )

        if not self.iso7816:
            state_hint = "No live session: start with reader.list and session.connect."
        elif not self.passport:
            state_hint = "Connected without high-level session: raw APDUs work; authenticate before LDS reads."
        elif self.iso7816.ciphering is None and getattr(self._access_control, "mechanism", "") != "NONE":
            state_hint = "Secure Messaging is absent: use session.authenticate or session.reset(kind=reauth)."
        else:
            state_hint = "The current session can execute the in-channel actions directly."
            recipe = [name for name in recipe if name not in {"reader.list", "session.connect"}]

        recipe = recipe[: max(1, min(max_actions, 12))]
        return {
            "goal": goal,
            "rationale": rationale,
            "state_hint": state_hint,
            "workflow": [
                {"step": index + 1, "action": name, "why": ACTION_SPECS[name].summary}
                for index, name in enumerate(recipe)
            ],
            "actions": [ACTION_SPECS[name].detailed() for name in recipe],
        }

    def execute(self, action: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Validate and run one lazy action through the generic MCP call tool."""

        arguments = dict(arguments or {})
        spec = ACTION_SPECS.get(action)
        if spec is None:
            raise ActionError("unknown_action", f"Unknown action {action!r}", details=self._similar_actions(action))
        errors = validate(spec.input_schema, arguments)
        if errors:
            raise ActionError(
                "invalid_arguments",
                "; ".join(errors[:5]),
                details={"action": action, "input_schema": spec.input_schema},
            )
        handler = getattr(self, f"_action_{action.replace('.', '_')}")
        with self._lock:
            try:
                result = handler(arguments)
            except ActionError:
                raise
            except reader.ReaderException as exc:
                raise ActionError(
                    "pcsc_unavailable",
                    str(exc),
                    details={"install": "epassportviewer"},
                ) from exc
            except ISO7816Exception as exc:
                sw = f"{exc.sw1:02X}{exc.sw2:02X}" if exc.sw1 is not None and exc.sw2 is not None else ""
                raise ActionError("card_error", str(exc.data), details={"status_word": sw}) from exc
            except Exception as exc:
                logging.exception("Action %s failed", action)
                raise ActionError("action_failed", str(exc)) from exc
        return {"ok": True, "action": action, "result": result, "session": self._brief_status()}

    # ------------------------------- session actions ----------------------------

    def _action_reader_list(self, _args: dict[str, Any]) -> dict[str, Any]:
        available = reader.list_readers()
        return {"readers": [{"index": index, "name": str(item)} for index, item in enumerate(available)]}

    def _action_session_connect(self, args: dict[str, Any]) -> dict[str, Any]:
        if self._viewer_bound:
            iso = self._require_iso()
            requested = str(args.get("reader", "")).strip()
            if requested and requested not in (self.reader_name, "0"):
                raise ActionError("viewer_owns_reader", "Select the requested reader in ePassportViewer")
            return {"reader": self.reader_name, "atr_hex": iso.get_atr().hex().upper(), "owner": "ePassportViewer"}
        selector = args.get("reader")
        self._disconnect_live()
        connection = reader.get_reader(selector)
        if connection is None:
            raise ActionError("reader_not_found", "No matching PC/SC reader is available")
        try:
            connection.connect()
        except Exception as exc:
            raise ActionError("card_not_available", f"Could not connect to a passport: {exc}") from exc
        self.connection = connection
        self.iso7816 = ISO7816(connection)
        self.iso7816.source = "mcp"
        self.reader_name = (
            str(connection.getReader()) if hasattr(connection, "getReader") else str(selector or "reader 0")
        )
        self.passport = None
        self._access_control = None
        self._reset_capture_state(clear_offline=True)
        atr = self.iso7816.get_atr()
        return {"reader": self.reader_name, "atr_hex": atr.hex().upper()}

    def _action_session_status(self, _args: dict[str, Any]) -> dict[str, Any]:
        status = self._brief_status()
        status["cached_files"] = [row["name"] for row in self._inventory_rows()]
        status["apdu_history_count"] = len(APDUHistory.get())
        status["last_fuzz_result_count"] = len(self._last_fuzz_results)
        return status

    def _action_session_authenticate(self, args: dict[str, Any]) -> dict[str, Any]:
        iso = self._require_iso()
        mode = args.get("access_control", "auto")
        mrz = self._resolve_mrz(args, allow_stored=True)
        can = self._resolve_can(args, allow_stored=True)
        if mode == "bac" and mrz is None:
            raise ActionError("credentials_required", "BAC requires an MRZ")
        if mode in {"pace", "auto"} and mrz is None and can is None:
            raise ActionError("credentials_required", f"{mode.upper()} requires an MRZ or CAN")

        if args.get("reset_before", True):
            iso.rst_connection_raw()
            self._access_control = None
        passport = self.passport
        identity_changed = (
            passport is None
            or str(mrz or "") != str(getattr(passport, "_mrz", None) or "")
            or (can or "") != (getattr(passport, "_can", None) or "")
        )
        if identity_changed:
            passport = EPassport(iso, mrz, select_aid=False)
            self.passport = passport
        assert passport is not None
        result = passport.open(mrz=mrz, access_control=mode, can=can)
        self.connection = iso.reader_connection
        if identity_changed:
            self._reset_capture_state(clear_offline=False)
        self._mrz = mrz
        self._can = can
        self._access_mode = mode
        self._access_control = result
        return self._access_result(result)

    def _action_session_reset(self, args: dict[str, Any]) -> dict[str, Any]:
        iso = self._require_iso()
        kind = args.get("kind", "raw")
        if kind == "raw":
            iso.rst_connection_raw()
            self._access_control = None
        elif kind == "emrtd":
            iso.rst_connection()
            self._access_control = NegotiationResult("NONE")
        else:
            mrz = self._mrz
            can = self._can
            mode = args.get("access_control", self._access_mode)
            if mode == "bac" and mrz is None:
                raise ActionError("credentials_required", "No retained MRZ is available for BAC re-authentication")
            if mode in {"pace", "auto"} and mrz is None and can is None:
                raise ActionError("credentials_required", "No retained MRZ or CAN is available for re-authentication")
            iso.rst_connection_raw()
            if self.passport is None:
                self.passport = EPassport(iso, mrz, select_aid=False)
            result = self.passport.open(mrz=mrz, access_control=mode, can=can)
            self._access_mode = mode
            self._access_control = result
        self.connection = iso.reader_connection
        if args.get("clear_cache") and self.passport is not None:
            dict.clear(self.passport)
            self._reset_capture_state(clear_offline=False)
        return self._brief_status()

    def _action_session_close(self, args: dict[str, Any]) -> dict[str, Any]:
        self._disconnect_live()
        if args.get("clear_history"):
            APDUHistory.get().clear()
        return {"connected": False, "apdu_history_count": len(APDUHistory.get())}

    # ------------------------------ transport actions --------------------------

    def _action_apdu_transmit(self, args: dict[str, Any]) -> dict[str, Any]:
        iso = self._require_iso()
        channel = args.get("channel", "current")
        request_hex = self._clean_hex(args["apdu_hex"])
        history_before = len(APDUHistory.get())
        if channel == "wire":
            response = iso.transmit_raw(request_hex, source="mcp-wire")
            if args.get("invalidate_sm", True):
                iso.ciphering = None
                self._access_control = None
        else:
            command = self._parse_short_apdu(request_hex)
            saved_ciphering = iso.ciphering
            if channel == "plaintext":
                iso.ciphering = None
            try:
                response = iso.transmit(command, "MCP APDU", full=True, source=f"mcp-{channel}")
            finally:
                if channel == "plaintext":
                    iso.ciphering = saved_ciphering
        history = APDUHistory.get()
        tx = history[-1] if len(history) > history_before else None
        result = self._response_payload(response)
        result["request_hex"] = request_hex
        result["channel"] = channel
        if tx is not None:
            result["wire_request_hex"] = tx.wire_request_hex
            result["wire_response_hex"] = tx.wire_response_hex
        return result

    def _action_apdu_history(self, args: dict[str, Any]) -> dict[str, Any]:
        items = APDUHistory.get().to_list()
        offset = int(args.get("offset", -20))
        limit = int(args.get("limit", 20))
        start = max(0, len(items) + offset) if offset < 0 else min(offset, len(items))
        page = items[start : start + limit]
        if not args.get("include_wire", True):
            for item in page:
                item.pop("wire_request_hex", None)
                item.pop("wire_response_hex", None)
        return {"total": len(items), "offset": start, "returned": len(page), "transactions": page}

    def _action_apdu_clear_history(self, _args: dict[str, Any]) -> dict[str, Any]:
        cleared = len(APDUHistory.get())
        APDUHistory.get().clear()
        return {"cleared": cleared}

    # ------------------------------- passport actions --------------------------

    def _action_passport_capture(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_passport()
        requested = [str(item) for item in args.get("files", [])]
        if not requested:
            requested = []
            if args.get("include_card_access", True):
                requested.append("CardAccess")
            self._capture_one("COM", bool(args.get("refresh")))
            requested.append("COM")
            com = self._cached_file("COM")
            if isinstance(com, Mapping):
                for tag in com.get("5C", []):
                    try:
                        name = converter.to_dg(tag)
                    except KeyError:
                        continue
                    if name not in requested:
                        requested.append(name)
            if args.get("include_sod", True):
                requested.append("SOD")
        else:
            if args.get("include_card_access", True) and "CardAccess" not in requested:
                requested.insert(0, "CardAccess")
            if args.get("include_sod", True) and "SOD" not in requested:
                requested.append("SOD")

        for name in requested:
            if name == "COM" and self._cached_file("COM") is not None and not args.get("refresh"):
                continue
            self._capture_one(name, bool(args.get("refresh")))
        rows = [row for row in self._inventory_rows() if row["name"] in requested]
        return {
            "requested": requested,
            "captured": rows,
            "errors": dict(self._acquisition_errors),
            "evidence": {
                name: self._acquisition_evidence[name] for name in requested if name in self._acquisition_evidence
            },
        }

    def _action_passport_read_file(self, args: dict[str, Any]) -> dict[str, Any]:
        name = self._normalise_file_name(args["name"])
        ef = self._cached_file(name)
        if ef is None or args.get("refresh"):
            if self.passport is None and self.iso7816 is None:
                raise ActionError("file_not_cached", f"{name} is not present in the offline case")
            if self.passport is None:
                self.passport = EPassport(self._require_iso(), None, select_aid=False)
            self._capture_one(name, bool(args.get("refresh")))
            ef = self._cached_file(name)
        if ef is None:
            evidence = self._acquisition_evidence.get(name)
            outcome = (evidence or {}).get("outcome", "inconclusive")
            raise ActionError(
                "file_denied" if outcome == "denied" else "file_read_failed",
                self._acquisition_errors.get(name, f"Could not read {name}"),
                details=evidence,
            )
        return self._file_payload(
            name,
            ef,
            args.get("view", "parsed"),
            int(args.get("raw_offset", 0)),
            int(args.get("raw_length", 4096)),
            int(args.get("max_binary_bytes", 256)),
        )

    def _action_passport_file_chunk(self, args: dict[str, Any]) -> dict[str, Any]:
        name = self._normalise_file_name(args["name"])
        ef = self._cached_file(name)
        if ef is None:
            raise ActionError("file_not_cached", f"Read or import {name} before requesting chunks")
        raw = bytes(ef.file)
        offset = int(args.get("offset", 0))
        data = raw[offset : offset + int(args.get("length", 4096))]
        return {
            "name": name,
            "file_length": len(raw),
            "offset": offset,
            "length": len(data),
            "eof": offset + len(data) >= len(raw),
            "hex": data.hex().upper(),
        }

    def _action_passport_inventory(self, _args: dict[str, Any]) -> dict[str, Any]:
        return {"files": self._inventory_rows(), "acquisition_errors": dict(self._acquisition_errors)}

    def _action_passport_filesystem(self, args: dict[str, Any]) -> dict[str, Any]:
        passport = self._require_passport()
        applications = [args["application"]] if args.get("application") else passport.file_system.applications()
        extra_fids = tuple(self._fid(value) for value in args.get("extra_fids", []))
        enumerated = []
        for application in applications:
            application = str(application).upper()
            probes = passport.file_system.enumerate(application, extra_fids=extra_fids)
            enumerated.append({
                "application": application,
                "files": [self._compact_value(item, 256) for item in probes],
            })
        return {"applications": [str(item).upper() for item in applications], "enumerated": enumerated}

    def _action_passport_read_by_fid(self, args: dict[str, Any]) -> dict[str, Any]:
        application = str(args["application"]).upper()
        fid = self._fid(args["fid"])
        ef = self._require_passport().file_system.read_file(
            application,
            fid,
            sfi=args.get("sfi"),
            maximum=int(args.get("maximum", 1024 * 1024)),
        )
        return self._file_payload(
            f"{application}:{fid}",
            ef,
            "both",
            int(args.get("raw_offset", 0)),
            int(args.get("raw_length", 4096)),
            256,
        )

    def _action_security_discover_files(self, args: dict[str, Any]) -> dict[str, Any]:
        application = str(args.get("application", EMRTD)).upper()
        maximum = int(args.get("max_probes", 512))
        read_data = bool(args.get("read_data", True))
        probe_bytes = int(args.get("probe_bytes", 16))
        known = {ref.fid: ref for ref in FILES if ref.application == application}
        com = self._cached_file("COM")
        advertised = set()
        if isinstance(com, Mapping):
            for tag in com.get("5C", []):
                try:
                    advertised.add(converter.to_dg(tag))
                except KeyError:
                    pass
        sod = self._cached_file("SOD")
        hashed = {
            f"DG{number}" for number in (sod.get("dg_hashes", {}) if isinstance(sod, Mapping) else {})
        }
        fids: list[str] = []
        if args.get("fid_start") or args.get("fid_end"):
            if not args.get("fid_start") or not args.get("fid_end"):
                raise ActionError("invalid_fid_range", "fid_start and fid_end must be supplied together")
            first, last = int(self._fid(args["fid_start"]), 16), int(self._fid(args["fid_end"]), 16)
            if last < first:
                raise ActionError("invalid_fid_range", "fid_end must be greater than or equal to fid_start")
            fids.extend(f"{value:04X}" for value in range(first, min(last, first + maximum - 1) + 1))
        else:
            fids.extend(known)
        results: list[dict[str, Any]] = []
        remaining = maximum
        for fid in dict.fromkeys(fids):
            if remaining <= 0:
                break
            response = self._probe_reference(application, fid, None, "fid", probe_bytes, read_data=read_data)
            response.update({"addressing": "fid", "fid": fid})
            if fid in known:
                response["logical_name"] = known[fid].name
                if known[fid].name.startswith("DG"):
                    response["advertised_in_com"] = known[fid].name in advertised
                    response["hashed_in_sod"] = known[fid].name in hashed
            results.append(response)
            remaining -= 1
        if args.get("probe_sfi", True):
            known_sfi = {ref.sfi: ref for ref in FILES if ref.application == application and ref.sfi is not None}
            for sfi in range(1, 32):
                if remaining <= 0:
                    break
                response = self._probe_reference(application, "", sfi, "sfi", probe_bytes, read_data=True)
                response.update({"addressing": "sfi", "sfi": sfi})
                if sfi in known_sfi:
                    response["logical_name"] = known_sfi[sfi].name
                    if known_sfi[sfi].name.startswith("DG"):
                        response["advertised_in_com"] = known_sfi[sfi].name in advertised
                        response["hashed_in_sod"] = known_sfi[sfi].name in hashed
                results.append(response)
                remaining -= 1
        candidates = [item for item in results if item["outcome"] not in {"absent", "rejected"}]
        return {
            "application": application,
            "probe_count": len(results),
            "truncated": remaining == 0
            and len(dict.fromkeys(fids)) + (31 if args.get("probe_sfi", True) else 0) > maximum,
            "candidates": candidates,
            "status_histogram": self._status_histogram(results),
        }

    def _action_passport_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        passport = self._require_passport()
        results: dict[str, Any] = {}
        if args.get("active_authentication", True):
            try:
                value = passport.do_active_authentication()
                self._checks["active_authentication"] = bool(value)
                self._checks.pop("active_authentication_error", None)
                results["active_authentication"] = {
                    "ok": bool(value),
                    "outcome": "pass" if value else "fail",
                }
            except Exception as exc:
                self._checks["active_authentication"] = None
                self._checks["active_authentication_error"] = str(exc)
                results["active_authentication"] = {"ok": None, "outcome": "inconclusive", "error": str(exc)}
        if args.get("data_group_integrity", True):
            try:
                integrity = passport.do_verify_dg_integrity()
                if isinstance(integrity, Mapping):
                    self._integrity = {str(key): value for key, value in integrity.items()}
                    results["data_group_integrity"] = {
                        "ok": all(value is not False for value in integrity.values()),
                        "outcome": "pass" if all(value is not False for value in integrity.values()) else "fail",
                        "files": dict(integrity),
                    }
                else:
                    results["data_group_integrity"] = {
                        "ok": None,
                        "outcome": "inconclusive",
                        "error": "No integrity result was returned",
                    }
            except Exception as exc:
                results["data_group_integrity"] = {"ok": None, "outcome": "inconclusive", "error": str(exc)}
        if args.get("sod_certificate", False):
            directory = args.get("csca_directory")
            if not directory:
                raise ActionError("csca_required", "sod_certificate=true requires csca_directory")
            try:
                self._configure_trust(passport, directory, args.get("master_list_signer_paths", []))
                verified = bool(passport.do_verify_sod_certificate())
                self._sod_verification = passport.sod_verification_info
                self._checks["sod_signature_verified"] = verified
                self._checks.pop("sod_signature_error", None)
                results["sod_certificate"] = {
                    "ok": verified,
                    "outcome": "pass" if verified else "fail",
                    "details": self._sod_verification,
                }
            except Exception as exc:
                self._checks["sod_signature_verified"] = None
                self._checks["sod_signature_error"] = str(exc)
                results["sod_certificate"] = {"ok": None, "outcome": "inconclusive", "error": str(exc)}
        return results

    def _action_security_chip_authentication(self, args: dict[str, Any]) -> dict[str, Any]:
        passport = self._require_passport()
        if args.get("csca_directory"):
            self._configure_trust(passport, args["csca_directory"], args.get("master_list_signer_paths", []))
        try:
            result = passport.do_chip_authentication(source=args.get("source", "DG14"), key_id=args.get("key_id"))
        except Exception as exc:
            self._checks["chip_authentication"] = None
            self._checks["chip_authentication_error"] = str(exc)
            raise
        self._checks["chip_authentication"] = True
        self._checks.pop("chip_authentication_error", None)
        return self._compact_value(result, 256)

    def _action_security_access_matrix(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_iso()
        states = list(args.get("states") or ["raw", "aid", "current"])
        names = list(args.get("files") or [ref.name for ref in FILES])
        paths = list(args.get("paths") or ["fid", "sfi", "odd_sfi", "plaintext_fid"])
        probe_bytes, maximum = int(args.get("probe_bytes", 8)), int(args.get("max_probes", 256))
        refs: list[FileReference] = []
        for name in names:
            try:
                refs.append(resolve_file(name))
            except KeyError as exc:
                raise ActionError("unknown_file", str(exc)) from exc
        cells: list[dict[str, Any]] = []
        for state in states:
            setup = self._setup_access_state(state, args)
            if setup["outcome"] != "pass":
                for ref in refs:
                    if len(cells) >= maximum:
                        break
                    cells.append({"state": state, "file": ref.name, "path": "state_setup", **setup})
                continue
            restore_needed = False
            for ref in refs:
                for path in paths:
                    if len(cells) >= maximum:
                        break
                    if path in {"sfi", "odd_sfi", "plaintext_sfi"} and ref.sfi is None:
                        continue
                    if restore_needed or path.startswith("plaintext_"):
                        setup = self._setup_access_state(state, args)
                        if setup["outcome"] != "pass":
                            cells.append({"state": state, "file": ref.name, "path": path, **setup})
                            continue
                    effective = path.removeprefix("plaintext_")
                    result = self._probe_reference(
                        ref.application, ref.fid, ref.sfi, effective, probe_bytes,
                        plaintext=path.startswith("plaintext_"), read_data=True, select_application=state != "raw",
                    )
                    cells.append({"state": state, "file": ref.name, "path": path, **result})
                    restore_needed = path.startswith("plaintext_")
                if len(cells) >= maximum:
                    break
            if len(cells) >= maximum:
                break
        restored: dict[str, Any] = {"outcome": "not_requested"}
        if args.get("restore_after", True):
            restored = self._setup_access_state("current", args)
        signals = []
        public = {"CardAccess", "CardSecurity", "DIR", "ATR/INFO", "CVCA"}
        for cell in cells:
            data = cell.get("data_length", 0)
            if data and cell["file"] not in public and (
                cell["state"] in {"raw", "aid", "none"} or cell["path"].startswith("plaintext_")
            ):
                signals.append({"type": "access_control_bypass", "cell": cell})
            if data and cell["file"] in {"DG3", "DG4"} and cell["state"] != "pace_ca_ta":
                signals.append({"type": "protected_biometric_exposed", "cell": cell})
        return {
            "cells": cells,
            "outcomes": self._outcome_histogram(cells),
            "security_signals": signals,
            "truncated": len(cells) >= maximum,
            "restored": restored,
        }

    def _action_security_aa_analysis(self, args: dict[str, Any]) -> dict[str, Any]:
        passport = self._require_passport()
        iso = self._require_iso()
        try:
            dg15, dg14 = passport["DG15"], passport["DG14"]
        except Exception as exc:
            raise ActionError("aa_evidence_required", f"DG15 and DG14 are required: {exc}") from exc
        ec_key = passport._aa._load_ec_public_key(dg15.body)
        pre: dict[str, Any] = {"outcome": "not_tested"}
        if args.get("test_pre_access", True):
            iso.rst_connection_raw()
            try:
                raw = APDUCommand("00", "88", "00", "00", data=b"\0" * 8, le="00").raw()
                response = iso.transmit_raw(raw, source="mcp-aa-pre-access")
                pre = {
                    **self._response_payload(response),
                    "outcome": "fail" if response.data else self._probe_outcome(response),
                }
                if response.data:
                    pre["security_signal"] = "AA signing oracle is available before access control"
            except Exception as exc:
                pre = {"outcome": "inconclusive", "error": str(exc)}
        setup = self._setup_access_state("current", args)
        samples: list[dict[str, Any]] = []
        rs: dict[int, int] = {}
        rounds = int(args.get("rounds", 8))
        if setup["outcome"] == "pass":
            for index in range(rounds):
                challenge = (index + 1).to_bytes(8, "big")
                try:
                    if ec_key is None:
                        verified = passport.do_active_authentication(dg15=dg15, strict=True)
                        signature = passport._aa.signature
                    else:
                        signature = iso.internal_authentication(challenge.hex())
                        verified = passport._aa.verify_ecdsa_signature(ec_key, dg14, challenge, signature, strict=True)
                    sample = {"challenge_index": index, "signature_length": len(signature), "outcome": "pass"}
                    if ec_key is not None:
                        sample["verified"] = verified
                        r, _s = passport._aa.ecdsa_signature_components(ec_key, signature)
                        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
                        sample["r_fingerprint"] = hashlib.sha256(r_bytes).hexdigest()[:16]
                        if r in rs:
                            sample["security_signal"] = f"ECDSA nonce reuse with challenge {rs[r]}"
                        else:
                            rs[r] = index
                    else:
                        sample["verified"] = bool(verified)
                    samples.append(sample)
                except Exception as exc:
                    samples.append({"challenge_index": index, "outcome": "inconclusive", "error": str(exc)})
                    break
        restored = (
            self._setup_access_state("current", args)
            if args.get("restore_after", True)
            else {"outcome": "not_requested"}
        )
        nonce_reuse = any("security_signal" in sample for sample in samples)
        verification_failures = any(sample.get("verified") is False for sample in samples)
        verification_complete = len(samples) == rounds and all(sample.get("verified") is True for sample in samples)
        return {
            "key_type": "ECDSA" if ec_key is not None else "RSA",
            "pre_access": pre,
            "post_access": samples,
            "signature_verification": {
                "outcome": "fail" if verification_failures else "pass" if verification_complete else "inconclusive"
            },
            "ecdsa_nonce_reuse": {
                "outcome": "fail"
                if nonce_reuse
                else "pass"
                if ec_key is not None and len(samples) == rounds
                else "inconclusive"
            },
            "private_key_export": {
                "outcome": "inconclusive",
                "readable": False,
                "evidence": "No export was observed; DG15 contains only public-key data and AA returned signatures",
            },
            "restored": restored,
        }

    def _action_security_terminal_authentication(self, args: dict[str, Any]) -> dict[str, Any]:
        passport = self._require_passport()
        chain = [self._credential_file(path, "terminal CVC") for path in args["terminal_chain_paths"]]
        anchors = [self._credential_file(path, "CVCA trust anchor") for path in args["trust_anchor_paths"]]
        key = self._credential_file(args["private_key_path"], "terminal private key")
        references = args.get("cvca_references_hex")
        references = [bytes.fromhex(self._clean_hex(value)) for value in references] if references else None
        id_picc = bytes.fromhex(self._clean_hex(args["id_picc_hex"]))
        if not id_picc:
            raise ActionError("invalid_id_picc", "id_picc_hex must not be empty")
        try:
            result = passport.do_terminal_authentication(
                chain,
                key,
                id_picc,
                cvca_references=references,
                trust_anchors=anchors,
                test_negative_rights=bool(args.get("test_negative_rights", True)),
            )
        except Exception as exc:
            self._checks["terminal_authentication"] = None
            self._checks["terminal_authentication_error"] = str(exc)
            raise
        self._checks["terminal_authentication"] = True
        self._checks["terminal_authentication_rights"] = result.get("rights")
        self._checks["terminal_negative_rights"] = result.get("negative_rights", [])
        return self._compact_value(result, 256)

    def _action_security_conformance(self, args: dict[str, Any]) -> dict[str, Any]:
        profile_args = {name: value for name, value in args.items() if name != "csca_directory"}
        profile = ConformanceProfile.from_mapping(profile_args)
        report = ConformanceRunner(self._require_passport()).run(
            profile,
            csca_directory=args.get("csca_directory"),
        )
        return report.to_dict()

    # ------------------------------- security actions --------------------------

    def _action_security_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        if args.get("capture_missing"):
            self._action_passport_capture({"include_card_access": True, "include_sod": True, "refresh": False})
        if args.get("run_live_checks", True) and self.passport is not None:
            self._action_passport_verify(
                {
                    "active_authentication": True,
                    "data_group_integrity": True,
                    "sod_certificate": bool(args.get("verify_sod_certificate")),
                    "csca_directory": args.get("csca_directory", ""),
                    "master_list_signer_paths": args.get("master_list_signer_paths", []),
                }
            )
        files = self._all_cached_files()
        if not files:
            raise ActionError("no_evidence", "Capture a passport or import a snapshot before building a report")
        atr: bytes | None = None
        uid: bytes | None = None
        iso = self.iso7816
        if iso is not None:
            try:
                atr = iso.get_atr()
            except Exception:
                pass
            if args.get("probe_uid"):
                try:
                    uid_response = iso.transmit_raw("FFCA000000", source="mcp-uid")
                    if (uid_response.sw1, uid_response.sw2) == (0x90, 0x00):
                        uid = bytes(uid_response.data)
                    else:
                        self._acquisition_errors["UID"] = f"SW={uid_response.sw1:02X}{uid_response.sw2:02X}"
                except Exception as exc:
                    self._acquisition_errors["UID"] = str(exc)
        report = build_security_report(
            files,
            access_control=self._access_control,
            atr=atr,
            uid=uid,
            sm_type=self._sm_type(),
            integrity=self._integrity,
            sod_verification=self._sod_verification,
            checks=self._checks,
            acquisition_errors=self._acquisition_errors,
        ).to_dict()
        if args.get("detail", "full") == "summary":
            return {
                "generated_at": report["generated_at"],
                "summary": report["summary"],
                "findings": report["findings"],
                "acquisition_errors": report["acquisition_errors"],
            }
        return cast(dict[str, Any], self._compact_value(report, 512))

    # ------------------------------- research actions --------------------------

    def _action_fuzz_run(self, args: dict[str, Any]) -> dict[str, Any]:
        iso = self._require_iso()
        seed = self._parse_short_apdu(self._clean_hex(args["seed_apdu_hex"]))
        channel = args.get("channel", "current")
        safety_profile = args.get("safety_profile", "read_only")
        if safety_profile == "read_only" and channel == "wire":
            raise ActionError(
                "unsafe_wire_fuzz",
                "wire mutation is opaque and requires safety_profile='research' plus reset_policy='before_each'",
            )
        if channel != "wire" and not args.get("include_state_changing", False) and int(seed.ins, 16) not in SAFE_INS:
            raise ActionError(
                "unsafe_seed",
                f"INS {seed.ins} is outside the read-only fuzz allowlist",
                details={"allowed_ins": [f"{value:02X}" for value in sorted(SAFE_INS)]},
            )
        if channel == "wire" and args.get("reset_policy") != "before_each":
            raise ActionError("unsafe_wire_reset", "wire fuzzing requires reset_policy='before_each'")
        strategies = args.get("strategies", list(DEFAULT_STRATEGIES))
        unknown = sorted(set(strategies) - set(STRATEGY_LABELS))
        if unknown:
            raise ActionError(
                "unknown_strategy",
                "Unknown fuzz strategies",
                details={"unknown": unknown, "available": STRATEGY_LABELS},
            )
        cases = generate_fuzz_cases(
            seed,
            strategies,
            max_cases=int(args.get("max_cases", 256)),
            include_state_changing=bool(args.get("include_state_changing", False)),
        )
        reset_kind = args.get("reset_kind", "raw")

        def reset_callback() -> None:
            if reset_kind == "reauth":
                self._action_session_reset({"kind": "reauth", "clear_cache": False})
            else:
                self._action_session_reset({"kind": "raw", "clear_cache": False})

        results = run_fuzz_campaign(
            iso,
            cases,
            channel=channel,
            repeat_each=int(args.get("repeat_each", 1)),
            delay_ms=int(args.get("delay_ms", 0)),
            reset_policy=args.get("reset_policy", "never"),
            reset_callback=reset_callback,
            source="mcp-fuzz",
        )
        self._last_fuzz_results = results
        recovery: dict[str, Any] = {"outcome": "not-requested"}
        if args.get("recover_after", True):
            kind = "reauth" if (self._mrz is not None or self._can is not None) else "raw"
            try:
                recovery = {"outcome": "pass", **self._action_session_reset({"kind": kind, "clear_cache": False})}
            except Exception as exc:
                recovery = {"outcome": "inconclusive", "error": str(exc)}
        interesting = [item.to_dict() for item in results if item.interesting]
        limit = int(args.get("interesting_limit", 20))
        return {
            "case_count": len(cases),
            "summary": summarize_fuzz_results(results),
            "interesting": interesting[:limit],
            "interesting_returned": min(len(interesting), limit),
            "recovery": recovery,
            "next": "Use fuzz.results for additional stored results.",
        }

    def _action_fuzz_results(self, args: dict[str, Any]) -> dict[str, Any]:
        items = self._last_fuzz_results
        if args.get("interesting_only", True):
            items = [item for item in items if item.interesting]
        offset = int(args.get("offset", 0))
        limit = int(args.get("limit", 50))
        return {
            "total": len(items),
            "offset": offset,
            "results": [item.to_dict() for item in items[offset : offset + limit]],
        }

    def _action_attack_mac_traceability(self, args: dict[str, Any]) -> dict[str, Any]:
        iso = self._require_iso()
        mrz = self._resolve_mrz(args, allow_stored=True)
        if mrz is None:
            raise ActionError("credentials_required", "MAC traceability requires a valid MRZ")
        try:
            vulnerable, evidence = MacTraceability(iso, mrz).is_vulnerable(float(args.get("cutoff_ms", 1.7)))
        finally:
            self._invalidate_access_state()
        return {"vulnerable": vulnerable, "evidence": evidence}

    def _action_attack_aa_before_access(self, _args: dict[str, Any]) -> dict[str, Any]:
        try:
            vulnerable = AATraceability(self._require_iso()).is_vulnerable()
        finally:
            self._invalidate_access_state()
        return {
            "vulnerable": vulnerable,
            "evidence": "INTERNAL AUTHENTICATE returned a signature before BAC/PACE"
            if vulnerable
            else "No pre-access signature returned",
        }

    def _action_attack_sign_challenge(self, args: dict[str, Any]) -> dict[str, Any]:
        challenge = self._clean_hex(args["challenge_hex"])
        if len(challenge) != 16:
            raise ActionError("invalid_challenge", "challenge_hex must contain exactly 8 bytes")
        mrz: MRZ | None = None
        if args.get("verify_with_dg15"):
            mrz = self._resolve_mrz(args, allow_stored=True)
            if mrz is None:
                raise ActionError("credentials_required", "DG15 verification requires an MRZ")
        try:
            signature, verified = SignEverything(self._require_iso()).sign(challenge, str(mrz) if mrz else None)
        finally:
            self._invalidate_access_state()
        return {"signature_hex": signature, "verified_with_dg15": verified if mrz else None}

    def _action_attack_aa_traceability(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            highest = AATraceability(self._require_iso()).get_highest_sign(int(args.get("rounds", 100)))
        finally:
            self._invalidate_access_state()
        return {"highest_signature_hex": highest, "rounds": int(args.get("rounds", 100))}

    def _action_attack_aa_compare(self, args: dict[str, Any]) -> dict[str, Any]:
        modulus = self._clean_hex(args["modulus_hex"])
        highest = self._clean_hex(args["highest_signature_hex"])
        return {
            "may_belong_to_same_passport": AATraceability.may_belong_to(modulus, highest),
            "relative_gap_percent": AATraceability.compare(modulus, highest),
        }

    def _action_attack_bac_bruteforce(self, args: dict[str, Any]) -> dict[str, Any]:
        mode = args["mode"]
        attack = BruteForce(self._require_iso() if mode == "online" else None)
        attack.set_id(args.get("document_number_low"), args.get("document_number_high"))
        attack.set_dob(args.get("date_of_birth_low"), args.get("date_of_birth_high"))
        attack.set_exp_date(args.get("expiry_low"), args.get("expiry_high"))
        valid, error = attack.check()
        if not valid:
            raise ActionError("invalid_search_range", error)
        id_stats = attack.get_id_stat()
        dob_stats = attack.get_dob_stat()
        expiry_stats = attack.get_exp_date_stat()
        candidates = id_stats[2] * dob_stats[2] * expiry_stats[2]
        if mode == "offline":
            captured = args.get("captured_pair_hex")
            if not captured:
                raise ActionError("captured_pair_required", "Offline mode requires captured_pair_hex")
            found = attack.exploit_offline(self._clean_hex(captured))
        else:
            try:
                found = attack.exploit(reset=bool(args.get("reset_each", True)))
            finally:
                self._invalidate_access_state()
        return {"found_mrz": found or None, "candidates": candidates, "mode": mode}

    # --------------------------------- case actions -----------------------------

    def _action_case_import_snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        path = Path(args["path"])
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ActionError("snapshot_read_failed", str(exc)) from exc
        if not isinstance(payload, Mapping) or int(payload.get("version", 0)) != 3:
            raise ActionError("invalid_snapshot", "Expected an ePassportViewer version 3 snapshot")
        imported: dict[str, Any] = {}
        file_maps = [payload.get("ef_raw", {}), payload.get("mf_ef_raw", {})]
        for file_map in file_maps:
            if not isinstance(file_map, Mapping):
                continue
            for name, raw_hex in file_map.items():
                if not isinstance(name, str) or not isinstance(raw_hex, str):
                    continue
                try:
                    logical = self._normalise_file_name(name)
                    tag = converter.to_tag(logical)
                    cls = getattr(data_group, converter.to_class(tag))
                    imported[logical] = cls(file=bytes.fromhex(raw_hex))
                except Exception as exc:
                    self._acquisition_errors[str(name)] = f"Snapshot parse failed: {exc}"
        if not imported:
            raise ActionError("invalid_snapshot", "Snapshot contained no readable elementary files")
        self._disconnect_live()
        self._offline_files = imported
        if args.get("replace_history", True):
            history_items = payload.get("apdu_history", [])
            APDUHistory.get().from_list(history_items if isinstance(history_items, list) else [], source="imported")
        context = payload.get("capture_context", {})
        if isinstance(context, Mapping):
            self._checks = dict(context.get("checks", {})) if isinstance(context.get("checks"), Mapping) else {}
            self._integrity = (
                dict(context.get("integrity", {})) if isinstance(context.get("integrity"), Mapping) else {}
            )
            verification = context.get("sod_verification")
            self._sod_verification = dict(verification) if isinstance(verification, Mapping) else None
        return {"path": str(path), "files": self._inventory_rows(), "apdu_history_count": len(APDUHistory.get())}

    def _action_case_export_snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        path = Path(args["path"])
        files = self._all_cached_files()
        ef_raw = {name: ef.file.hex().upper() for name, ef in files.items() if name != "CardAccess"}
        mf_raw = {"CardAccess": files["CardAccess"].file.hex().upper()} if "CardAccess" in files else {}
        payload = {
            "version": 3,
            "mrz": {"doc_number": "", "dob": "", "expiry": "", "can": ""},
            "ef_raw": ef_raw,
            "mf_ef_raw": mf_raw,
            "apdu_history": APDUHistory.get().to_list(),
            "capture_context": {
                "access_control": self._access_result(self._access_control) if self._access_control else {},
                "secure_messaging": self._sm_type() or "none",
                "integrity": self._integrity,
                "checks": self._checks,
                "sod_verification": self._sod_verification,
                "live_details": {"atr": "", "uid": "", "acquisition_errors": self._acquisition_errors},
            },
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            raise ActionError("snapshot_write_failed", str(exc)) from exc
        return {"path": str(path), "file_count": len(files), "apdu_history_count": len(APDUHistory.get())}

    # ---------------------------------- helpers ----------------------------------

    def error_payload(self, action: str, exc: ActionError) -> dict[str, Any]:
        return {
            "ok": False,
            "action": action,
            "error": {"code": exc.code, "message": str(exc), "details": self._compact_value(exc.details, 1024)},
            "session": self._brief_status(),
        }

    def _similar_actions(self, action: str) -> dict[str, Any]:
        token = action.lower().split(".")[-1]
        matches = [spec.compact() for spec in ACTION_SPECS.values() if token in spec.name.lower()]
        return {"suggestions": matches[:8], "groups": GROUPS}

    def _disconnect_live(self) -> None:
        live_connection = self.iso7816.reader_connection if self.iso7816 is not None else self.connection
        if live_connection is not None:
            try:
                live_connection.disconnect()
            except Exception:
                logging.debug("Ignoring reader disconnect failure", exc_info=True)
        self.connection = None
        self.iso7816 = None
        self.passport = None
        self.reader_name = ""
        self._access_control = None

    def _require_iso(self) -> ISO7816:
        if self.iso7816 is None:
            raise ActionError("not_connected", "Call session.connect before a live action")
        return self.iso7816

    def _require_passport(self) -> EPassport:
        if self.passport is None:
            raise ActionError("passport_not_open", "Call session.authenticate before a high-level live action")
        return self.passport

    def _resolve_mrz(self, args: Mapping[str, Any], *, allow_stored: bool) -> MRZ | None:
        raw = args.get("mrz")
        if raw is None:
            return self._mrz if allow_stored else None
        if isinstance(raw, list):
            raw = tuple(str(item) for item in raw)
        try:
            value = MRZ(raw)
            if not value.check_mrz():
                raise ValueError("MRZ check digits are invalid")
        except Exception as exc:
            raise ActionError("invalid_mrz", str(exc)) from exc
        return value

    def _resolve_can(self, args: Mapping[str, Any], *, allow_stored: bool) -> str | None:
        raw = args.get("can", self._can if allow_stored else None)
        return str(raw).strip() or None if raw is not None else None

    @staticmethod
    def _clean_hex(raw: Any) -> str:
        clean = "".join(str(raw).split()).replace(":", "").upper()
        if len(clean) % 2:
            raise ActionError("invalid_hex", "Hexadecimal has an odd number of digits")
        try:
            bytes.fromhex(clean)
        except ValueError as exc:
            raise ActionError("invalid_hex", "Value is not valid hexadecimal") from exc
        return clean

    @classmethod
    def _fid(cls, raw: Any) -> str:
        value = cls._clean_hex(raw)
        if len(value) != 4:
            raise ActionError("invalid_fid", "Each FID must contain exactly two bytes")
        return value

    @staticmethod
    def _credential_file(raw_path: Any, description: str) -> bytes:
        path = Path(str(raw_path)).expanduser()
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ActionError("credential_read_failed", f"Cannot read {description}: {exc}") from exc
        if not data or len(data) > 1024 * 1024:
            raise ActionError("invalid_credential_file", f"{description} must contain 1..1048576 bytes")
        return data

    @staticmethod
    def _parse_short_apdu(raw_hex: str) -> APDUCommand:
        raw = bytes.fromhex(raw_hex)
        if len(raw) < 4:
            raise ActionError(
                "invalid_apdu",
                "A normal short APDU needs at least four header bytes; use channel=wire for shorter frames",
            )
        cla, ins, p1, p2 = (f"{value:02X}" for value in raw[:4])
        body = raw[4:]
        if not body:
            return APDUCommand(cla, ins, p1, p2)
        if len(body) == 1:
            return APDUCommand(cla, ins, p1, p2, le=f"{body[0]:02X}")
        size = body[0]
        rest = body[1:]
        if len(rest) == size:
            return APDUCommand(cla, ins, p1, p2, lc=f"{size:02X}", data=rest.hex().upper())
        if len(rest) == size + 1:
            return APDUCommand(cla, ins, p1, p2, lc=f"{size:02X}", data=rest[:size].hex().upper(), le=f"{rest[-1]:02X}")
        raise ActionError("invalid_apdu", "Lc/data length mismatch; use channel=wire to preserve a malformed frame")

    def _capture_one(self, name: str, refresh: bool) -> None:
        passport = self._require_passport()
        logical = self._normalise_file_name(name)
        tag = converter.to_tag(logical)
        if refresh:
            dict.pop(passport, tag, None)
        try:
            ef = passport[logical]
            if ef is None:
                evidence = dict(getattr(passport, "read_errors", {}).get(logical, {}))
                if not evidence:
                    evidence = {
                        "outcome": "inconclusive",
                        "phase": "select_or_read",
                        "message": "chip returned no parsed data",
                        "status_word": "",
                    }
                self._acquisition_evidence[logical] = evidence
                raise RuntimeError(self._format_failure_evidence(evidence))
            self._acquisition_errors.pop(logical, None)
            history = APDUHistory.get()
            last = history[-1] if history else None
            self._acquisition_evidence[logical] = {
                "outcome": "pass",
                "phase": "read_and_parse",
                "status_word": (
                    f"{last.response_sw1:02X}{last.response_sw2:02X}" if last is not None else ""
                ),
                "response_authenticated": last.response_authenticated if last is not None else None,
                "length": len(ef.file),
            }
        except Exception as exc:
            self._acquisition_errors[logical] = str(exc)
            self._acquisition_evidence.setdefault(
                logical,
                {"outcome": "inconclusive", "phase": "read_or_parse", "message": str(exc), "status_word": ""},
            )

    def _configure_trust(self, passport: EPassport, directory: Any, signer_paths: list[Any]) -> None:
        signers = [self._credential_file(path, "Master List signer") for path in signer_paths]
        passport.configure_trust_store(directory, master_list_signers=signers)

    def _setup_access_state(self, state: str, args: Mapping[str, Any]) -> dict[str, Any]:
        try:
            if state == "raw":
                self._require_iso().rst_connection_raw()
                self._access_control = None
                result = self._brief_status()
            elif state in {"aid", "none"}:
                result = self._action_session_reset({"kind": "emrtd", "clear_cache": False})
            else:
                mode = self._access_mode if state == "current" else "pace" if state.startswith("pace_") else state
                result = self._action_session_reset({"kind": "reauth", "access_control": mode, "clear_cache": False})
                if state in {"pace_ca", "pace_ca_ta"}:
                    directory = args.get("csca_directory")
                    if not directory:
                        raise ActionError("csca_required", f"{state} requires csca_directory")
                    passport = self._require_passport()
                    self._configure_trust(passport, directory, list(args.get("master_list_signer_paths", [])))
                    ca = passport.do_chip_authentication(source="DG14")
                    result = {**result, "chip_authentication": self._compact_value(ca, 128)}
                if state == "pace_ca_ta":
                    chain_paths = list(args.get("terminal_chain_paths", []))
                    key_path = args.get("terminal_private_key_path")
                    anchor_paths = list(args.get("terminal_trust_anchor_paths", []))
                    if not chain_paths or not key_path or not anchor_paths or not args.get("id_picc_hex"):
                        raise ActionError(
                            "ta_credentials_required", "pace_ca_ta requires terminal credentials and ID_PICC"
                        )
                    ta = passport.do_terminal_authentication(
                        [self._credential_file(path, "terminal CVC") for path in chain_paths],
                        self._credential_file(key_path, "terminal private key"),
                        bytes.fromhex(self._clean_hex(args["id_picc_hex"])),
                        trust_anchors=[self._credential_file(path, "CVCA trust anchor") for path in anchor_paths],
                    )
                    result = {**result, "terminal_authentication": self._compact_value(ta, 128)}
            return {"outcome": "pass", "state_details": result}
        except Exception as exc:
            return {"outcome": "inconclusive", "phase": "state_setup", "error": str(exc)}

    def _probe_reference(self, application: str, fid: str, sfi: int | None, path: str, probe_bytes: int,
                         *, plaintext=False, read_data=True, select_application=True) -> dict[str, Any]:
        iso = self._require_iso()
        saved = iso.ciphering
        if plaintext:
            iso.ciphering = None

        def exchange(command: APDUCommand, phase: str) -> tuple[APDUResponse | None, dict[str, Any] | None]:
            try:
                response = iso.transmit(command, full=True, source="mcp-access-matrix")
                evidence = self._probe_evidence(response, phase)
                return response, evidence
            except Exception as exc:
                return None, {"outcome": "inconclusive", "phase": phase, "error": str(exc)}

        try:
            if select_application:
                app_command = (
                    APDUCommand("00", "A4", "00", "0C", data="3F00")
                    if application == MF
                    else APDUCommand("00", "A4", "04", "0C", data=application)
                )
                selected, evidence = exchange(app_command, "select_application")
                if selected is None or selected.sw1 not in (0x90, 0x62, 0x63):
                    return cast(dict[str, Any], evidence)
                iso.current_application = application
            if path == "fid":
                selected, evidence = exchange(APDUCommand("00", "A4", "02", "0C", data=fid), "select_file")
                if selected is None or selected.sw1 not in (0x90, 0x62, 0x63) or not read_data:
                    return cast(dict[str, Any], evidence)
                command = APDUCommand("00", "B0", "00", "00", le=probe_bytes)
            elif path == "sfi":
                command = APDUCommand("00", "B0", f"{0x80 | int(sfi or 0):02X}", "00", le=probe_bytes)
            elif path == "odd_sfi":
                command = APDUCommand(
                    "00", "B1", "00", "00", data=bytes([0x51, 1, int(sfi or 0), 0x54, 1, 0]), le=probe_bytes
                )
            else:
                raise ActionError("invalid_probe_path", path)
            _response, evidence = exchange(command, "read")
            return cast(dict[str, Any], evidence)
        finally:
            if plaintext:
                iso.ciphering = saved

    @classmethod
    def _probe_evidence(cls, response: APDUResponse, phase: str) -> dict[str, Any]:
        data = bytes(response.data)
        evidence: dict[str, Any] = {
            "outcome": cls._probe_outcome(response),
            "phase": phase,
            "status_word": f"{response.sw1:02X}{response.sw2:02X}",
            "response_authenticated": response.authenticated,
            "data_length": len(data),
        }
        if data:
            evidence["data_prefix_hex"] = data[:32].hex().upper()
            evidence["data_sha256"] = hashlib.sha256(data).hexdigest()
            if response.authenticated is False:
                evidence["security_signal"] = "unauthenticated_data_under_secure_messaging"
        return evidence

    @staticmethod
    def _probe_outcome(response: APDUResponse) -> str:
        if response.data:
            return "data"
        sw = (response.sw1 << 8) | response.sw2
        if response.sw1 in (0x90, 0x62, 0x63):
            return "pass"
        if sw in {0x6982, 0x6985, 0x6987, 0x6988}:
            return "denied"
        if sw in {0x6A82, 0x6A83, 0x6A88, 0x6B00}:
            return "absent"
        if sw in {0x6983, 0x6984, 0x6581}:
            return "blocked"
        return "rejected"

    @staticmethod
    def _status_histogram(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
        output: dict[str, int] = {}
        for row in rows:
            value = str(row.get("status_word") or row.get("outcome", "inconclusive"))
            output[value] = output.get(value, 0) + 1
        return output

    @staticmethod
    def _outcome_histogram(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
        output: dict[str, int] = {}
        for row in rows:
            value = str(row.get("outcome", "inconclusive"))
            output[value] = output.get(value, 0) + 1
        return output

    @staticmethod
    def _format_failure_evidence(evidence: Mapping[str, Any]) -> str:
        message = str(evidence.get("message", "could not read file"))
        status_word = str(evidence.get("status_word", ""))
        return f"{message} (SW={status_word})" if status_word else message

    def _normalise_file_name(self, name: str) -> str:
        try:
            return resolve_file(name).name
        except KeyError:
            pass
        try:
            tag = converter.to_tag(name)
            return converter.to_dg(tag)
        except KeyError as exc:
            raise ActionError("unknown_file", f"Unknown elementary file {name!r}") from exc

    def _cached_file(self, name: str) -> Any | None:
        logical = self._normalise_file_name(name)
        if self.passport is not None:
            tag = converter.to_tag(logical)
            if tag in self.passport:
                return dict.__getitem__(self.passport, tag)
        return self._offline_files.get(logical)

    def _all_cached_files(self) -> dict[str, Any]:
        files = dict(self._offline_files)
        if self.passport is not None:
            for tag, ef in dict.items(self.passport):
                try:
                    name = converter.to_dg(tag)
                except KeyError:
                    name = str(tag)
                files[name] = ef
        return files

    def _inventory_rows(self) -> list[dict[str, Any]]:
        rows = []
        for name, ef in sorted(self._all_cached_files().items(), key=lambda item: self._file_sort_key(item[0])):
            raw = bytes(ef.file)
            parse_errors = ef.get("parse_errors", []) if isinstance(ef, Mapping) else []
            rows.append(
                {
                    "name": name,
                    "tag": getattr(ef, "tag", ""),
                    "length": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "parse_error_count": len(parse_errors) if isinstance(parse_errors, list) else 0,
                }
            )
        return rows

    def _file_payload(self, name: str, ef: Any, view: str, offset: int, length: int, max_binary: int) -> dict[str, Any]:
        raw = bytes(ef.file)
        result = {
            "name": name,
            "tag": getattr(ef, "tag", ""),
            "length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        if view in {"parsed", "both"}:
            parsed = ef.to_json_dict() if hasattr(ef, "to_json_dict") else dict(ef)
            if isinstance(parsed, Mapping):
                parsed = dict(parsed)
                parsed.pop("raw_file_hex", None)
                parsed.pop("raw_body_hex", None)
            result["parsed"] = self._compact_value(parsed, max_binary)
        if view in {"raw", "both"}:
            chunk = raw[offset : offset + length]
            result["raw"] = {
                "offset": offset,
                "length": len(chunk),
                "eof": offset + len(chunk) >= len(raw),
                "hex": chunk.hex().upper(),
            }
        return result

    def _brief_status(self) -> dict[str, Any]:
        mechanism = getattr(self._access_control, "mechanism", "none") if self._access_control is not None else "none"
        return {
            "connected": self.iso7816 is not None,
            "reader": self.reader_name,
            "access_control": mechanism,
            "secure_messaging": self._sm_type() or "none",
            "cached_file_count": len(self._all_cached_files()),
        }

    def _sm_type(self) -> str:
        ciphering = self.iso7816.ciphering if self.iso7816 is not None else None
        if ciphering is None:
            return ""
        return "AES" if "Aes" in type(ciphering).__name__ else "3DES"

    def _reset_capture_state(self, *, clear_offline: bool) -> None:
        if clear_offline:
            self._offline_files = {}
        self._checks = {}
        self._integrity = {}
        self._sod_verification = None
        self._acquisition_errors = {}
        self._acquisition_evidence = {}
        self._last_fuzz_results = []

    def _invalidate_access_state(self) -> None:
        if self.iso7816 is not None:
            self.iso7816.ciphering = None
            self.connection = self.iso7816.reader_connection
        self._access_control = None

    @staticmethod
    def _access_result(result: NegotiationResult) -> dict[str, Any]:
        payload: dict[str, Any] = {"mechanism": result.mechanism}
        if result.fallback_reason:
            payload["fallback_reason"] = result.fallback_reason
            payload["downgraded"] = result.downgraded
        if result.attempts:
            payload["attempts"] = result.attempts
        if result.pace_info is not None:
            payload["pace"] = {
                "oid": result.pace_info.oid,
                "key_agreement": result.pace_info.key_agreement,
                "mapping": result.pace_info.mapping,
                "cipher": result.pace_info.cipher,
                "key_size": result.pace_info.key_size,
                "parameter_id": result.pace_info.parameter_id,
            }
        return payload

    @staticmethod
    def _response_payload(response: APDUResponse) -> dict[str, Any]:
        return {
            "response_data_hex": to_hex_string(response.data) if response.data else "",
            "status_word": f"{response.sw1:02X}{response.sw2:02X}",
            "sw1": response.sw1,
            "sw2": response.sw2,
            "status": APDUResponse.describe(response.sw1, response.sw2),
        }

    @classmethod
    def _compact_value(cls, value: Any, max_binary: int) -> Any:
        if isinstance(value, bytes):
            if len(value) <= max_binary:
                return value.hex().upper()
            return {
                "binary_length": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
                "hex_preview": value[:32].hex().upper(),
            }
        if isinstance(value, Mapping):
            return {str(key): cls._compact_value(item, max_binary) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [cls._compact_value(item, max_binary) for item in value]
        if is_dataclass(value):
            return cls._compact_value(asdict(cast(Any, value)), max_binary)
        return value

    @staticmethod
    def _file_sort_key(name: str) -> tuple[int, str]:
        order = {"CardAccess": 0, "COM": 1, "SOD": 2}
        if name in order:
            return (order[name], name)
        if name.startswith("DG") and name[2:].isdigit():
            return (2 + int(name[2:]), name)
        return (99, name)
