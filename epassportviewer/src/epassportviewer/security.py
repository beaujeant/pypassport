"""Security workbench for eMRTD reconnaissance and posture review."""

from __future__ import annotations

import json
import logging
import threading
import tkinter as tk
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from pypassport.doc9303 import converter
from pypassport.doc9303.data_group import _CLASS_MAP
from pypassport.doc9303.security_info import PACEInfo
from pypassport.doc9303.file_context import EMRTD
from pypassport.security_audit import SecurityReport, build_security_report

from . import theme
from .fuzzing import FuzzingPane


_REPORT_FILES = ("COM", "SOD", "CardSecurity") + tuple(f"DG{index}" for index in range(1, 17))


@dataclass(frozen=True)
class SecurityProbe:
    name: str
    apdu: str
    channel: str
    purpose: str


_PROBES = (
    SecurityProbe("Select MF", "00A4000C023F00", "Plaintext", "Return to the master file before probing MF-level EFs."),
    SecurityProbe(
        "Select eMRTD AID",
        "00A4040C07A0000002471001",
        "Plaintext",
        "Select the ICAO eMRTD application by AID.",
    ),
    SecurityProbe(
        "Select EF.CardAccess",
        "00A4020C02011C",
        "Plaintext",
        "Select the pre-authentication PACE capability file under the MF.",
    ),
    SecurityProbe(
        "Select EF.CardSecurity",
        "00A4020C02011D",
        "SM",
        "Select authenticated MF-level EAC SecurityInfos, not LDS EF.SOD.",
    ),
    SecurityProbe("Select EF.COM", "00A4020C02011E", "SM", "Select the LDS inventory file."),
    SecurityProbe("Select EF.SOD", "00A4020C02011D", "SM", "Select the passive-authentication security object."),
    SecurityProbe("Select DG14", "00A4020C02010E", "SM", "Select SecurityInfos for AA/CA/TA/EAC review."),
    SecurityProbe("Select DG15", "00A4020C02010F", "SM", "Select the Active Authentication public key."),
    SecurityProbe("Read first 4 bytes", "00B0000004", "Current", "Read a selected EF header and declared length."),
    SecurityProbe("Read via SFI 1", "00B0810004", "Current", "Probe short-file-ID reads and SFI access controls."),
    SecurityProbe("Odd READ BINARY", "00B100000454027FFF00", "Current", "Exercise enhanced offsets independently of even-INS reads."),
    SecurityProbe("Extended READ BINARY", "00B0000000000100", "Current", "Request 256 bytes with case-2E under the current channel."),
    SecurityProbe("Get Challenge", "0084000008", "Plaintext", "Exercise BAC/AA challenge behavior and status words."),
    SecurityProbe("GET RESPONSE", "00C0000000", "Current", "Request pending response bytes after a 61xx status."),
    SecurityProbe(
        "MSE:Set AT empty",
        "0022C1A4",
        "Plaintext",
        "Probe PACE security-environment handling with an empty data field.",
    ),
    SecurityProbe(
        "GENERAL AUTHENTICATE empty",
        "10860000027C0000",
        "Plaintext",
        "Probe PACE GENERAL AUTHENTICATE parsing with an empty dynamic-authentication template.",
    ),
    SecurityProbe(
        "Internal Authenticate",
        "0088000008112233445566778800",
        "Current",
        "Probe AA behavior with a deterministic 64-bit challenge.",
    ),
    SecurityProbe(
        "Malformed SELECT length",
        "00A4020C053F00",
        "Plaintext",
        "Observe error handling for an inconsistent Lc/data pair.",
    ),
)


@dataclass(frozen=True)
class _CapturedAccessControl:
    """Minimal access-control state retained in an offline session snapshot."""

    mechanism: str
    pace_info: PACEInfo | None = None


def _json_safe(value: Any) -> Any:
    """Return a JSON-friendly copy of capture metadata."""

    if isinstance(value, bytes):
        return value.hex().upper()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if is_dataclass(value):
        return _json_safe(asdict(value))
    return value


def _serialise_access_control(access_control: Any) -> dict[str, Any] | None:
    if access_control is None:
        return None

    mechanism = getattr(access_control, "mechanism", None)
    pace_info = getattr(access_control, "pace_info", None)
    if mechanism is None and pace_info is None:
        return None

    payload: dict[str, Any] = {"mechanism": str(mechanism or "unknown")}
    if isinstance(pace_info, PACEInfo):
        payload["pace_info"] = {
            "oid": pace_info.oid,
            "version": pace_info.version,
            "parameter_id": pace_info.parameter_id,
        }
    return payload


def _restore_access_control(payload: Any) -> _CapturedAccessControl | None:
    if not isinstance(payload, Mapping):
        return None

    mechanism = payload.get("mechanism")
    if not isinstance(mechanism, str) or not mechanism:
        return None

    pace_info = None
    raw_pace_info = payload.get("pace_info")
    if isinstance(raw_pace_info, Mapping):
        oid = raw_pace_info.get("oid")
        version = raw_pace_info.get("version")
        parameter_id = raw_pace_info.get("parameter_id")
        if isinstance(oid, str) and isinstance(version, int):
            pace_info = PACEInfo(
                oid=oid,
                version=version,
                parameter_id=parameter_id if isinstance(parameter_id, int) else None,
            )
    return _CapturedAccessControl(mechanism=mechanism, pace_info=pace_info)


class SecurityPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self.tab = self.root.security_tab
        self._report: SecurityReport | None = None
        self._files: dict[str, Any] = {}
        self._cached_checks_ep: Any = None
        self._cached_checks: dict[str, Any] = {}
        self._cached_integrity: dict[str, bool | None] = {}
        self._cached_atr: bytes | str | None = None
        self._cached_uid: bytes | str | None = None
        self._cached_acquisition_errors: dict[str, str] = {}
        self._cached_access_control: Any = None
        self._cached_sm_type = "none"
        self._cached_sod_verification: Mapping[str, Any] | None = None
        self.root.security_pane = self

        self._build_ui()

    def _build_ui(self):
        toolbar = ttk.Frame(self.tab)
        toolbar.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Button(toolbar, text="Refresh report", command=self.refresh_cached).pack(side="left", padx=(0, 4))
        ttk.Button(toolbar, text="Export JSON", command=self._export_report).pack(side="left", padx=4)
        self._run_status = tk.StringVar(value="Read a passport in View to populate this report.")
        ttk.Label(toolbar, textvariable=self._run_status, style="Muted.TLabel").pack(side="right", padx=4)

        status = ttk.Frame(self.tab)
        status.pack(fill="x", padx=8, pady=(0, 6))
        self._status_vars = {
            "access": tk.StringVar(value="Access: -"),
            "sm": tk.StringVar(value="SM: -"),
            "atr": tk.StringVar(value="ATR: -"),
            "uid": tk.StringVar(value="UID: -"),
            "anomalies": tk.StringVar(value="Anomalies: -"),
        }
        for key in ("access", "sm", "atr", "uid", "anomalies"):
            ttk.Label(status, textvariable=self._status_vars[key], style="Caption.TLabel").pack(
                side="left", padx=(0, 18)
            )

        notebook = ttk.Notebook(self.tab)
        self._notebook = notebook
        notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        findings_tab = ttk.Frame(notebook)
        protocols_tab = ttk.Frame(notebook)
        files_tab = ttk.Frame(notebook)
        attacks_tab = ttk.Frame(notebook)
        self.attacks_tab = attacks_tab
        fuzzing_tab = ttk.Frame(notebook)
        self._fuzzing_tab = fuzzing_tab
        probes_tab = ttk.Frame(notebook)
        advanced_tab = ttk.Frame(notebook)
        notebook.add(findings_tab, text="Findings")
        notebook.add(protocols_tab, text="Protocols")
        notebook.add(files_tab, text="Files")
        notebook.add(attacks_tab, text="Attacks")
        notebook.add(fuzzing_tab, text="Fuzzing")
        notebook.add(probes_tab, text="Probes")
        notebook.add(advanced_tab, text="Advanced protocols")

        self._build_findings(findings_tab)
        self._build_protocols(protocols_tab)
        self._build_files(files_tab)
        self.fuzzing_pane = FuzzingPane(self.parent, fuzzing_tab, self, _PROBES)
        self._build_probes(probes_tab)
        self._build_advanced_protocols(advanced_tab)

    def _build_findings(self, parent):
        paned = ttk.Panedwindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        columns = ("severity", "category", "title")
        self._findings_tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        self._findings_tree.heading("severity", text="Severity")
        self._findings_tree.heading("category", text="Category")
        self._findings_tree.heading("title", text="Finding")
        self._findings_tree.column("severity", width=80, stretch=False)
        self._findings_tree.column("category", width=120, stretch=False)
        self._findings_tree.column("title", width=460, stretch=True)
        self._findings_tree.tag_configure("high", background=theme.ERR_BG)
        self._findings_tree.tag_configure("medium", background=theme.WARN_BG)
        self._findings_tree.tag_configure("low", background="#FFF6D8")
        self._findings_tree.tag_configure("info", background=theme.SURFACE_ALT)
        self._findings_tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self._findings_tree.yview)
        scroll.pack(side="right", fill="y")
        self._findings_tree.configure(yscrollcommand=scroll.set)
        self._findings_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)

        self._finding_detail = tk.Text(right, wrap="word", state="disabled")
        theme.style_text(self._finding_detail)
        self._finding_detail.pack(side="left", fill="both", expand=True)
        detail_scroll = ttk.Scrollbar(right, orient="vertical", command=self._finding_detail.yview)
        detail_scroll.pack(side="right", fill="y")
        self._finding_detail.configure(yscrollcommand=detail_scroll.set)

    def _build_protocols(self, parent):
        paned = ttk.Panedwindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=4)
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=2)
        paned.add(right, weight=3)

        self._protocol_tree = ttk.Treeview(left, columns=("value",), show="tree headings", selectmode="browse")
        self._protocol_tree.heading("#0", text="Protocol area")
        self._protocol_tree.heading("value", text="Summary")
        self._protocol_tree.column("#0", width=210, stretch=False)
        self._protocol_tree.column("value", width=280, stretch=True)
        self._protocol_tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self._protocol_tree.yview)
        scroll.pack(side="right", fill="y")
        self._protocol_tree.configure(yscrollcommand=scroll.set)
        self._protocol_tree.bind("<<TreeviewSelect>>", self._on_protocol_selected)

        self._protocol_detail = tk.Text(right, wrap="none", state="disabled")
        theme.style_text(self._protocol_detail)
        self._protocol_detail.pack(side="left", fill="both", expand=True)
        detail_scroll = ttk.Scrollbar(right, orient="vertical", command=self._protocol_detail.yview)
        detail_scroll.pack(side="right", fill="y")
        self._protocol_detail.configure(yscrollcommand=detail_scroll.set)

    def _build_files(self, parent):
        paned = ttk.Panedwindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=4)
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=2)
        paned.add(right, weight=3)

        columns = ("tag", "length", "integrity", "parse")
        self._files_tree = ttk.Treeview(left, columns=columns, show="tree headings", selectmode="browse")
        self._files_tree.heading("#0", text="EF")
        self._files_tree.heading("tag", text="Tag")
        self._files_tree.heading("length", text="Bytes")
        self._files_tree.heading("integrity", text="SOD")
        self._files_tree.heading("parse", text="Parse")
        self._files_tree.column("#0", width=120, stretch=False)
        self._files_tree.column("tag", width=62, stretch=False)
        self._files_tree.column("length", width=72, stretch=False)
        self._files_tree.column("integrity", width=84, stretch=False)
        self._files_tree.column("parse", width=120, stretch=True)
        self._files_tree.tag_configure("parse_error", background="#FFF6D8")
        self._files_tree.tag_configure("integrity_error", background=theme.ERR_BG)
        self._files_tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self._files_tree.yview)
        scroll.pack(side="right", fill="y")
        self._files_tree.configure(yscrollcommand=scroll.set)
        self._files_tree.bind("<<TreeviewSelect>>", self._on_file_selected)

        self._file_detail = tk.Text(right, wrap="none", state="disabled")
        theme.style_text(self._file_detail)
        self._file_detail.pack(side="left", fill="both", expand=True)
        detail_scroll = ttk.Scrollbar(right, orient="vertical", command=self._file_detail.yview)
        detail_scroll.pack(side="right", fill="y")
        self._file_detail.configure(yscrollcommand=detail_scroll.set)

    def _build_probes(self, parent):
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", padx=4, pady=(4, 0))
        ttk.Button(toolbar, text="Load selected into Forge", command=self._load_selected_probe).pack(side="left")
        self._probe_detail_var = tk.StringVar(value="Select a probe to inspect its purpose.")
        ttk.Label(toolbar, textvariable=self._probe_detail_var, style="Muted.TLabel").pack(side="left", padx=12)

        columns = ("channel", "apdu")
        self._probes_tree = ttk.Treeview(parent, columns=columns, show="tree headings", selectmode="browse")
        self._probes_tree.heading("#0", text="Probe")
        self._probes_tree.heading("channel", text="Channel")
        self._probes_tree.heading("apdu", text="APDU")
        self._probes_tree.column("#0", width=220, stretch=False)
        self._probes_tree.column("channel", width=100, stretch=False)
        self._probes_tree.column("apdu", width=620, stretch=True)
        self._probes_tree.pack(fill="both", expand=True, padx=4, pady=4)
        self._probes_tree.bind("<<TreeviewSelect>>", self._on_probe_selected)
        self._probes_tree.bind("<Double-1>", lambda _event: self._load_selected_probe())
        for index, probe in enumerate(_PROBES):
            self._probes_tree.insert("", "end", iid=str(index), text=probe.name, values=(probe.channel, probe.apdu))

    def _build_advanced_protocols(self, parent):
        filesystem = ttk.LabelFrame(parent, text="Application-qualified filesystem")
        filesystem.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        fs_toolbar = ttk.Frame(filesystem)
        fs_toolbar.pack(fill="x", padx=4, pady=4)
        ttk.Label(fs_toolbar, text="Application/AID:").pack(side="left")
        self._fs_application = tk.StringVar(value=EMRTD)
        ttk.Entry(fs_toolbar, textvariable=self._fs_application, width=22).pack(side="left", padx=(4, 10))
        ttk.Label(fs_toolbar, text="Extra FIDs:").pack(side="left")
        self._fs_extra_fids = tk.StringVar()
        ttk.Entry(fs_toolbar, textvariable=self._fs_extra_fids, width=24).pack(side="left", padx=4)
        ttk.Button(fs_toolbar, text="Discover applications", command=self._discover_filesystems).pack(side="left", padx=4)
        ttk.Button(fs_toolbar, text="Probe", command=self._probe_filesystem).pack(side="left", padx=4)
        self._fs_tree = ttk.Treeview(
            filesystem,
            columns=("fid", "sfi", "selected", "sw", "control"),
            show="tree headings",
        )
        for column, title, width in (
            ("#0", "Application / EF", 210),
            ("fid", "FID", 70),
            ("sfi", "SFI", 55),
            ("selected", "Selected", 75),
            ("sw", "SW", 65),
            ("control", "FCI/FCP", 310),
        ):
            self._fs_tree.heading(column, text=title)
            self._fs_tree.column(column, width=width, stretch=column == "control")
        self._fs_tree.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._fs_tree.bind("<Double-1>", lambda _event: self._read_selected_filesystem_file())
        self._fs_refs: dict[str, tuple[str, str, int | None]] = {}

        auth = ttk.LabelFrame(parent, text="Extended Access Control")
        auth.pack(fill="x", padx=8, pady=(4, 8))
        ca_row = ttk.Frame(auth)
        ca_row.pack(fill="x", padx=4, pady=4)
        ttk.Label(ca_row, text="CA source:").pack(side="left")
        self._ca_source = tk.StringVar(value="DG14")
        ttk.Combobox(ca_row, textvariable=self._ca_source, values=("DG14", "CardSecurity"), state="readonly", width=14).pack(
            side="left", padx=4
        )
        ttk.Label(ca_row, text="Key ID:").pack(side="left", padx=(10, 0))
        self._ca_key_id = tk.StringVar()
        ttk.Entry(ca_row, textvariable=self._ca_key_id, width=8).pack(side="left", padx=4)
        ttk.Button(ca_row, text="Run Chip Authentication", command=self._run_chip_authentication).pack(side="left", padx=8)

        ta_row = ttk.Frame(auth)
        ta_row.pack(fill="x", padx=4, pady=4)
        self._ta_chain_paths: tuple[str, ...] = ()
        self._ta_anchor_paths: tuple[str, ...] = ()
        self._ta_key_path = ""
        ttk.Button(ta_row, text="Choose IS/DV chain", command=self._choose_ta_chain).pack(side="left", padx=2)
        ttk.Button(ta_row, text="Choose terminal key", command=self._choose_ta_key).pack(side="left", padx=2)
        ttk.Button(ta_row, text="Choose CVCA anchors", command=self._choose_ta_anchors).pack(side="left", padx=2)
        ttk.Label(ta_row, text="ID_PICC hex:").pack(side="left", padx=(10, 0))
        self._ta_id_picc = tk.StringVar()
        ttk.Entry(ta_row, textvariable=self._ta_id_picc, width=24).pack(side="left", padx=4)
        ttk.Button(ta_row, text="Run TA", command=self._run_terminal_authentication).pack(side="left", padx=8)
        self._protocol_output = tk.Text(auth, height=5, wrap="word", state="disabled")
        theme.style_text(self._protocol_output)
        self._protocol_output.pack(fill="x", padx=4, pady=(2, 4))

    @staticmethod
    def _sm_type(ciphering) -> str:
        if ciphering is None:
            return "none"
        return "AES" if "Aes" in type(ciphering).__name__ else "3DES"

    def _reset_capture_cache(self, ep: Any) -> None:
        self._cached_checks_ep = ep
        self._cached_checks = {}
        self._cached_integrity = {}
        self._cached_atr = None
        self._cached_uid = None
        self._cached_acquisition_errors = {}
        self._cached_access_control = None
        self._cached_sm_type = "none"
        self._cached_sod_verification = None

    def _sync_live_capture_metadata(self, ep: Any) -> None:
        if ep is None:
            return
        self._cached_access_control = getattr(ep, "access_control", None)
        self._cached_sm_type = self._sm_type(ep.iso7816.ciphering)
        self._cached_sod_verification = getattr(ep, "sod_verification_info", None)

    def get_snapshot_metadata(self) -> dict[str, Any]:
        """Return analyst-facing capture context that raw EF bytes cannot recreate."""

        ep = self.parent.ep
        if ep is not self._cached_checks_ep:
            self._reset_capture_cache(ep)
        if ep is not None:
            self._sync_live_capture_metadata(ep)
        return {
            "access_control": _serialise_access_control(self._cached_access_control),
            "secure_messaging": self._cached_sm_type,
            "integrity": _json_safe(self._cached_integrity),
            "checks": _json_safe(self._cached_checks),
            "live_details": {
                "atr": _json_safe(self._cached_atr),
                "uid": _json_safe(self._cached_uid),
                "acquisition_errors": _json_safe(self._cached_acquisition_errors),
            },
            "sod_verification": _json_safe(self._cached_sod_verification),
        }

    def load_snapshot_metadata(self, payload: Any) -> bool:
        """Restore optional capture context from an imported offline session."""

        data = payload if isinstance(payload, Mapping) else {}
        self._cached_checks_ep = self.parent.ep
        self._cached_access_control = _restore_access_control(data.get("access_control"))
        sm_type = data.get("secure_messaging")
        self._cached_sm_type = sm_type if isinstance(sm_type, str) and sm_type else "none"

        checks = data.get("checks")
        self._cached_checks = dict(checks) if isinstance(checks, Mapping) else {}

        integrity = data.get("integrity")
        self._cached_integrity = {}
        if isinstance(integrity, Mapping):
            self._cached_integrity = {
                str(name): result
                for name, result in integrity.items()
                if isinstance(result, bool) or result is None
            }

        live_details = data.get("live_details")
        if isinstance(live_details, Mapping):
            atr = live_details.get("atr")
            uid = live_details.get("uid")
            acquisition_errors = live_details.get("acquisition_errors")
            self._cached_atr = atr if isinstance(atr, (bytes, str)) else None
            self._cached_uid = uid if isinstance(uid, (bytes, str)) else None
            self._cached_acquisition_errors = (
                {str(name): str(error) for name, error in acquisition_errors.items()}
                if isinstance(acquisition_errors, Mapping)
                else {}
            )
        else:
            self._cached_atr = None
            self._cached_uid = None
            self._cached_acquisition_errors = {}

        sod_verification = data.get("sod_verification")
        self._cached_sod_verification = dict(sod_verification) if isinstance(sod_verification, Mapping) else None
        return self.refresh_cached()

    def refresh_cached(
        self,
        *,
        checks: Mapping[str, Any] | None = None,
        integrity: Mapping[str, bool | None] | None = None,
        live_details: Mapping[str, Any] | None = None,
    ) -> bool:
        """Render a report from files already loaded by the View tab.

        This path does not perform any additional card reads. It is used by the
        manual refresh button and by the View pane after a passport read
        completes. Integrity results, live reader details, and verification
        results supplied by the View tab are remembered for the current passport
        session so subsequent refreshes keep the same report state.
        """
        ep = self.parent.ep
        if ep is not self._cached_checks_ep:
            self._reset_capture_cache(ep)
        self._sync_live_capture_metadata(ep)
        if checks is not None:
            self._cached_checks.update(checks)
        if integrity is not None:
            self._cached_integrity = dict(integrity)
        if live_details is not None:
            self._cached_atr = live_details.get("atr")
            self._cached_uid = live_details.get("uid")
            self._cached_acquisition_errors = dict(live_details.get("acquisition_errors", {}))

        files = self._cached_files()
        if not files:
            self._clear_report("Read a passport in View before refreshing the report.")
            return False
        report = build_security_report(
            files,
            access_control=self._cached_access_control,
            atr=self._cached_atr,
            uid=self._cached_uid,
            sm_type=self._cached_sm_type,
            integrity=self._cached_integrity,
            sod_verification=self._cached_sod_verification,
            checks=self._cached_checks,
            acquisition_errors=self._cached_acquisition_errors,
        )
        self._render_report(report, files)
        return True

    def _clear_report(self, status: str) -> None:
        self._report = None
        self._files = {}
        for key in ("access", "sm", "atr", "uid", "anomalies"):
            label = key.upper() if key in ("atr", "uid") else key.capitalize()
            self._status_vars[key].set(f"{label}: -")
        self._findings_tree.delete(*self._findings_tree.get_children())
        self._protocol_tree.delete(*self._protocol_tree.get_children())
        self._files_tree.delete(*self._files_tree.get_children())
        self._set_text(self._finding_detail, "Read a passport in View to populate this report.")
        self._set_text(self._protocol_detail, "Read a passport in View to populate this report.")
        self._set_text(self._file_detail, "Read a passport in View to populate this report.")
        self._set_run_status(status)

    def _cached_files(self) -> dict[str, Any]:
        files: dict[str, Any] = {}
        ep = self.parent.ep
        if ep is not None:
            for name in ("CardAccess",) + _REPORT_FILES:
                if name in ep:
                    files[name] = dict.__getitem__(ep, name)
        if files:
            return files

        raw_files = getattr(self.parent.viewer_pane, "_ef_raw", {})
        for name, raw_hex in raw_files.items():
            try:
                tag = converter.to_tag(name)
                class_name = converter.to_class(tag)
                files[name] = _CLASS_MAP[class_name](file=bytes.fromhex(raw_hex))
            except Exception:
                continue
        return files

    def _render_report(self, report: SecurityReport, files: dict[str, Any]):
        self._report = report
        self._files = files
        summary = report.summary
        self._status_vars["access"].set(f"Access: {summary.get('access_control', '-')}")
        self._status_vars["sm"].set(f"SM: {summary.get('secure_messaging', '-')}")
        self._status_vars["atr"].set(f"ATR: {self._short(summary.get('atr', ''))}")
        self._status_vars["uid"].set(f"UID: {self._short(summary.get('uid', ''))}")
        self._status_vars["anomalies"].set(f"Anomalies: {summary.get('parser_anomaly_count', 0)}")
        self._set_run_status(f"Report covers {summary.get('captured_file_count', 0)} files, {len(report.findings)} findings.")
        self._render_findings(report)
        self._render_protocols(report)
        self._render_files(report)

    @staticmethod
    def _short(value: Any, limit: int = 24) -> str:
        text = str(value or "-")
        return text if len(text) <= limit else text[:limit] + "..."

    def _render_findings(self, report: SecurityReport):
        self._findings_tree.delete(*self._findings_tree.get_children())
        for index, finding in enumerate(report.findings):
            self._findings_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(finding.severity.upper(), finding.category, finding.title),
                tags=(finding.severity,),
            )
        self._set_text(self._finding_detail, "Select a finding to inspect its evidence.")
        children = self._findings_tree.get_children()
        if children:
            self._findings_tree.selection_set(children[0])
            self._on_finding_selected()

    def _render_protocols(self, report: SecurityReport):
        self._protocol_tree.delete(*self._protocol_tree.get_children())
        for name, value in report.protocols.items():
            self._protocol_tree.insert("", "end", iid=name, text=name.replace("_", " ").title(), values=(self._protocol_summary(value),))
        self._set_text(self._protocol_detail, "Select a protocol area to inspect its JSON.")

    @staticmethod
    def _protocol_summary(value: Any) -> str:
        if isinstance(value, list):
            return f"{len(value)} entr{'y' if len(value) == 1 else 'ies'}"
        if isinstance(value, dict):
            mechanism = value.get("mechanism")
            if mechanism:
                return str(mechanism)
            if "dg15_present" in value:
                return "DG15 present" if value["dg15_present"] else "DG15 absent"
            if "sod_present" in value:
                return "SOD present" if value["sod_present"] else "SOD absent"
        return str(value)

    def _render_files(self, report: SecurityReport):
        self._files_tree.delete(*self._files_tree.get_children())
        for row in report.files:
            integrity = row.get("integrity")
            integrity_text = "-" if integrity is None else ("OK" if integrity else "MISMATCH")
            parse_text = "OK" if not row["parse_errors"] else f"{len(row['parse_errors'])} issue(s)"
            tags = []
            if row["parse_errors"]:
                tags.append("parse_error")
            if integrity is False:
                tags.append("integrity_error")
            self._files_tree.insert(
                "",
                "end",
                iid=row["name"],
                text=row["name"],
                values=(row.get("tag", ""), row.get("length", "-"), integrity_text, parse_text),
                tags=tuple(tags),
            )
        self._set_text(self._file_detail, "Select an EF to inspect its parsed and raw JSON.")

    def _on_finding_selected(self, _event=None):
        if self._report is None:
            return
        selected = self._findings_tree.selection()
        if not selected:
            return
        finding = self._report.findings[int(selected[0])]
        lines = [
            f"{finding.severity.upper()}  {finding.category}",
            "",
            finding.title,
            "",
            "Evidence",
            finding.evidence,
        ]
        if finding.recommendation:
            lines.extend(("", "Next step", finding.recommendation))
        self._set_text(self._finding_detail, "\n".join(lines))

    def _on_protocol_selected(self, _event=None):
        if self._report is None:
            return
        selected = self._protocol_tree.selection()
        if not selected:
            return
        value = self._report.protocols[selected[0]]
        self._set_text(self._protocol_detail, json.dumps(value, indent=2, sort_keys=True))

    def _on_file_selected(self, _event=None):
        selected = self._files_tree.selection()
        if not selected:
            return
        ef = self._files.get(selected[0])
        if ef is None:
            return
        try:
            text = ef.to_json()
        except Exception:
            text = repr(ef)
        self._set_text(self._file_detail, text)

    def _on_probe_selected(self, _event=None):
        selected = self._probes_tree.selection()
        if not selected:
            return
        self._probe_detail_var.set(_PROBES[int(selected[0])].purpose)

    def _load_selected_probe(self):
        selected = self._probes_tree.selection()
        if not selected:
            return
        probe = _PROBES[int(selected[0])]
        if hasattr(self.root, "forge_pane"):
            self.root.forge_pane.load_apdu(probe.apdu, label=probe.name)
            self.root.main_notebook.select(self.root.forge_tab)

    def load_fuzz_seed(self, raw_hex: str, *, label: str = ""):
        self.fuzzing_pane.load_seed(raw_hex, label=label)
        self._notebook.select(self._fuzzing_tab)
        self.root.main_notebook.select(self.root.security_tab)

    def _advanced_ep(self):
        ep = self.parent.ep
        if ep is None:
            self._set_protocol_text("Read and authenticate a passport first.")
        return ep

    def _advanced_task(self, label: str, operation, complete=None):
        self._set_protocol_text(label + "...")

        def worker():
            try:
                with self.parent.card_operation(f"GUI: {label}"):
                    result = operation()
                error = None
            except Exception as exc:
                logging.warning("%s failed: %s", label, exc)
                result, error = None, str(exc)

            def finish():
                if error:
                    self._set_protocol_text(label + " failed: " + error)
                elif complete:
                    complete(result)
                else:
                    self._set_protocol_text(json.dumps(_json_safe(result), indent=2, sort_keys=True))

            self.parent.viewer_pane._post(finish)

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _parse_fids(value: str) -> tuple[str, ...]:
        result = []
        for item in value.replace(",", " ").split():
            item = item.upper()
            if len(item) != 4 or any(character not in "0123456789ABCDEF" for character in item):
                raise ValueError(f"FID {item!r} must contain exactly four hexadecimal characters")
            result.append(item)
        return tuple(result)

    def _discover_filesystems(self):
        ep = self._advanced_ep()
        if ep is None:
            return
        try:
            extra_fids = self._parse_fids(self._fs_extra_fids.get())
        except ValueError as exc:
            self._set_protocol_text(str(exc))
            return

        def operation():
            applications = ep.file_system.applications()
            return [(application, ep.file_system.enumerate(application, extra_fids=extra_fids)) for application in applications]

        self._advanced_task("Discovering application files", operation, self._render_filesystems)

    def _probe_filesystem(self):
        ep = self._advanced_ep()
        if ep is None:
            return
        application = self._fs_application.get().strip().upper() or EMRTD
        try:
            extra_fids = self._parse_fids(self._fs_extra_fids.get())
        except ValueError as exc:
            self._set_protocol_text(str(exc))
            return
        self._advanced_task(
            f"Probing {application}",
            lambda: [(application, ep.file_system.enumerate(application, extra_fids=extra_fids))],
            self._render_filesystems,
        )

    def _render_filesystems(self, applications):
        self._fs_tree.delete(*self._fs_tree.get_children())
        self._fs_refs = {}
        selected = 0
        for app_index, (application, probes) in enumerate(applications):
            parent = f"app-{app_index}"
            self._fs_tree.insert("", "end", iid=parent, text=application)
            for probe_index, probe in enumerate(probes):
                selected += bool(probe.selected)
                control = probe.control or {}
                summary = ", ".join(
                    f"{name}={control[name]}" for name in ("file_size", "total_file_size") if name in control
                )
                item = f"{parent}-{probe_index}"
                self._fs_tree.insert(
                    parent,
                    "end",
                    iid=item,
                    text=probe.logical_name or "unknown",
                    values=(probe.fid, probe.sfi or "", "yes" if probe.selected else "no", probe.sw, summary),
                )
                if probe.selected:
                    self._fs_refs[item] = (application, probe.fid, probe.sfi)
        self._set_protocol_text(f"Probed {sum(len(row[1]) for row in applications)} files; selected {selected}.")

    def _read_selected_filesystem_file(self):
        selected = self._fs_tree.selection()
        if not selected or selected[0] not in self._fs_refs:
            return
        ep = self._advanced_ep()
        if ep is None:
            return
        application, fid, sfi = self._fs_refs[selected[0]]
        self._advanced_task(
            f"Reading {application}:{fid}",
            lambda: ep.file_system.read_file(application, fid, sfi=sfi),
            lambda ef: self._set_protocol_text(ef.to_json()),
        )

    def _run_chip_authentication(self):
        ep = self._advanced_ep()
        if ep is None:
            return
        trust = str(self.parent.settings.csca_dir).strip()
        if not trust:
            self._set_protocol_text("Configure a trusted CSCA/Master List directory before Chip Authentication.")
            return
        raw_key_id = self._ca_key_id.get().strip()
        try:
            key_id = int(raw_key_id, 0) if raw_key_id else None
        except ValueError:
            self._set_protocol_text("CA key ID must be a decimal number or 0x-prefixed integer.")
            return

        def operation():
            ep.csca_directory = trust
            return ep.do_chip_authentication(source=self._ca_source.get(), key_id=key_id)

        def complete(result):
            self._cached_checks["chip_authentication"] = True
            self.refresh_cached(checks={"chip_authentication": True})
            self._set_protocol_text(json.dumps(_json_safe(result), indent=2, sort_keys=True))

        self._advanced_task("Running Chip Authentication", operation, complete)

    def _choose_ta_chain(self):
        self._ta_chain_paths = tuple(
            filedialog.askopenfilenames(title="Choose terminal CVCs in leaf-first order", parent=self.root)
        )
        self._set_protocol_text(f"Selected {len(self._ta_chain_paths)} terminal CVC file(s).")

    def _choose_ta_key(self):
        self._ta_key_path = filedialog.askopenfilename(title="Choose terminal private key", parent=self.root)
        self._set_protocol_text("Terminal key selected." if self._ta_key_path else "Terminal key selection cancelled.")

    def _choose_ta_anchors(self):
        self._ta_anchor_paths = tuple(
            filedialog.askopenfilenames(title="Choose explicit CVCA CVC trust anchors", parent=self.root)
        )
        self._set_protocol_text(f"Selected {len(self._ta_anchor_paths)} CVCA trust anchor(s).")

    def _run_terminal_authentication(self):
        ep = self._advanced_ep()
        if ep is None:
            return
        if not self._ta_chain_paths or not self._ta_key_path or not self._ta_anchor_paths:
            self._set_protocol_text("Choose the leaf-first CVC chain, terminal key, and explicit CVCA anchor(s).")
            return
        try:
            id_picc = bytes.fromhex("".join(self._ta_id_picc.get().split()))
        except ValueError:
            self._set_protocol_text("ID_PICC must be valid hexadecimal.")
            return
        if not id_picc:
            self._set_protocol_text("ID_PICC must not be empty.")
            return

        def operation():
            chain = [Path(path).read_bytes() for path in self._ta_chain_paths]
            anchors = [Path(path).read_bytes() for path in self._ta_anchor_paths]
            return ep.do_terminal_authentication(
                chain,
                Path(self._ta_key_path).read_bytes(),
                id_picc,
                trust_anchors=anchors,
            )

        def complete(result):
            self.refresh_cached(checks={
                "terminal_authentication": True,
                "terminal_authentication_rights": result["rights"],
                "terminal_negative_rights": result.get("negative_rights", []),
            })
            self._set_protocol_text(json.dumps(_json_safe(result), indent=2, sort_keys=True))

        self._advanced_task("Running Terminal Authentication", operation, complete)

    def _set_protocol_text(self, text: str):
        self._set_text(self._protocol_output, text)

    def _export_report(self):
        if self._report is None:
            self._set_run_status("Read a passport or refresh the report before exporting.")
            return
        path = filedialog.asksaveasfilename(
            title="Export security report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        Path(path).write_text(self._report.to_json() + "\n", encoding="utf-8")
        self._set_run_status(f"Exported report to {path}")

    def _set_run_status(self, text: str):
        self._run_status.set(text)

    @staticmethod
    def _set_text(widget: tk.Text, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")
