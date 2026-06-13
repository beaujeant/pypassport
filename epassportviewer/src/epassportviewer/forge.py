import logging
import tkinter as tk
from tkinter import ttk, messagebox
from pypassport.iso7816 import ISO7816, APDUCommand, APDUResponse
from pypassport.apdu_history import APDUHistory
from pypassport.utils import toHexString
from pypassport.doc9303.mrz import MRZ
from pypassport.doc9303.access_control import (
    AccessControlNegotiator,
    AccessControlNegotiationError,
    MODE_BAC,
    MODE_PACE,
)

from .hexdump import HexDumpView, build_legend
from .apdu_format import parse_apdu, assemble_apdu


# Common request templates, mirroring the buttons under Custom > Requests.
# Selecting one fills the request header fields below; any field a preset
# omits falls back to _PRESET_DEFAULTS.
_PRESET_PLACEHOLDER = "Common requests…"
_RESP_STATUS_HINT = "Send a request to see the status-word translation here."
_RESP_DUMP_HINT = "Send a request to see the response bytes here."
_PRESET_DEFAULTS = {"cla": "00", "ins": "00", "p1": "00", "p2": "00", "lc": "", "data": "", "le": "00"}
_REQUEST_PRESETS = {
    "External Authenticate": {"ins": "82", "le": "28"},
    "Internal Authenticate": {"ins": "88"},
    "Select File":           {"ins": "A4", "p1": "02", "p2": "0C", "le": ""},
    "Read Binary":           {"ins": "B0"},
    "Rehabilitate":          {"ins": "44"},
    "Get UID":               {"cla": "FF", "ins": "CA", "p1": "00", "p2": "00"},
    "Get ATS":               {"cla": "FF", "ins": "CA", "p1": "01", "p2": "00"},
    "Get Challenge":         {"ins": "84", "le": "08"},
}

# How many forged requests to keep in memory (Burp-Repeater style tabs). When a
# new request pushes past this, the oldest tab is dropped.
_MAX_REQUESTS = 12


class _ForgeRequest:
    """In-memory state for one Forge request tab.

    Holds the editable request fields plus the last response captured for this
    tab, so switching between tabs restores both the request and its result.
    """

    def __init__(self, cla="", ins="", p1="", p2="", lc="", data="", le="", raw_mode=False):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.lc = lc
        self.data = data
        self.le = le
        self.raw_mode = raw_mode
        # Last response captured for this tab.
        self.resp_data = ""
        self.resp_sw1 = None
        self.resp_sw2 = None
        self.resp_status = _RESP_STATUS_HINT
        # The APDUTransaction recorded for the last send, used by "Send to
        # Comparer". None until the tab has been sent at least once.
        self.last_tx = None


class ForgePane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root

        # Set to True once the user explicitly forces "None" while an SM
        # channel is active, so the default selection stops snapping back to
        # the active SM on every refresh.
        self._sm_user_forced_none = False

        # Burp-Repeater style request tabs. Always at least one.
        self._requests = [_ForgeRequest()]
        self._active = 0

        frame = self.root.forge_tab

        # ── Request tab strip ────────────────────────────────────────────────
        # A row of numbered tabs, each keeping its own request and last
        # response. "+" opens a fresh tab; "✕" closes the current one.
        tabbar = ttk.Frame(frame)
        tabbar.pack(fill="x", padx=5, pady=(8, 0))
        ttk.Label(tabbar, text="Requests:").pack(side="left", padx=(3, 6))
        self._tabstrip = ttk.Frame(tabbar)
        self._tabstrip.pack(side="left", fill="x", expand=True)
        ttk.Button(tabbar, text="✕", width=3, command=self._close_request).pack(side="right", padx=2)
        ttk.Button(tabbar, text="+", width=3, command=self._add_request).pack(side="right", padx=2)

        # ── Request ──────────────────────────────────────────────────────────
        req_frame = ttk.LabelFrame(frame, text=" Request ", padding=10)
        req_frame.pack(fill="x", padx=5, pady=8)

        # Preset selector + raw-mode toggle.
        row0 = ttk.Frame(req_frame)
        row0.pack(fill="x", pady=3)
        ttk.Label(row0, text="Preset:").pack(side="left", padx=(8, 2))
        self._preset_var = tk.StringVar(value=_PRESET_PLACEHOLDER)
        preset_combo = ttk.Combobox(
            row0, textvariable=self._preset_var, state="readonly", width=22,
            values=[_PRESET_PLACEHOLDER] + list(_REQUEST_PRESETS),
        )
        preset_combo.pack(side="left")
        preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # Raw mode: edit the whole command APDU as one hex string instead of
        # the individual fields. Toggling converts between the two views.
        self._raw_mode = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row0, text="Raw (paste full APDU hex)",
            variable=self._raw_mode, command=self._toggle_raw,
        ).pack(side="right", padx=8)

        # Fielded view: CLA / INS / P1 / P2 / LC / LE on one row, DATA below.
        self._fields_row = ttk.Frame(req_frame)
        for label, width, attr in (
            ("CLA", 3, "cla"),
            ("INS", 3, "ins"),
            ("P1",  3, "p1"),
            ("P2",  3, "p2"),
            ("LC",  4, "lc"),
            ("LE",  4, "le"),
        ):
            ttk.Label(self._fields_row, text=f"{label}:").pack(side="left", padx=(8, 2))
            var = tk.StringVar()
            setattr(self, f"_{attr}", var)
            ttk.Entry(self._fields_row, textvariable=var, width=width).pack(side="left")

        self._data_row = ttk.Frame(req_frame)
        ttk.Label(self._data_row, text="DATA:").pack(side="left", padx=(8, 2))
        self._data = tk.StringVar()
        ttk.Entry(self._data_row, textvariable=self._data, width=80).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )

        # Raw view: a single wide entry for the full command APDU hex.
        self._raw_row = ttk.Frame(req_frame)
        ttk.Label(self._raw_row, text="APDU (hex):").pack(side="left", padx=(8, 2))
        self._raw = tk.StringVar()
        ttk.Entry(self._raw_row, textvariable=self._raw, width=80).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )

        # SM selector + Send. Kept after the request rows so it stays put when
        # the fielded/raw rows are swapped in and out.
        self._sm_row = ttk.Frame(req_frame)
        self._sm_row.pack(fill="x", pady=5)
        # SM selector. Defaults to whatever Secure Messaging channel is already
        # in place (BAC/PACE), so sends are encrypted transparently. The user
        # can force "None" to send a single plaintext APDU without tearing down
        # the shared channel.
        ttk.Label(self._sm_row, text="SM:").pack(side="left", padx=(8, 2))
        self._sm_var = tk.StringVar(value="None")
        self._sm_combo = ttk.Combobox(
            self._sm_row, textvariable=self._sm_var, state="readonly", width=14,
            values=["None"], postcommand=self._refresh_sm_options,
        )
        self._sm_combo.pack(side="left")
        self._sm_combo.bind("<<ComboboxSelected>>", self._on_sm_choice)

        ttk.Button(self._sm_row, text="Send APDU", command=self._send).pack(side="right", padx=8)

        # ── Secure messaging session ─────────────────────────────────────────
        # Once a Secure Messaging channel desyncs — e.g. a failed read leaves
        # the Send Sequence Counter out of step and every following command
        # comes back 6882 — it stays broken until the channel is rebuilt. These
        # controls reset the card and re-run BAC/PACE from the MRZ/CAN entered
        # at the top of the window, giving a clean channel to keep working with.
        sm_frame = ttk.LabelFrame(frame, text=" Secure messaging session ", padding=10)
        sm_frame.pack(fill="x", padx=5, pady=8)

        sm_row = ttk.Frame(sm_frame)
        sm_row.pack(fill="x")
        ttk.Button(sm_row, text="Reset card", command=self._reset_card).pack(side="left", padx=(8, 3))
        ttk.Button(sm_row, text="Redo BAC", command=lambda: self._reestablish(MODE_BAC)).pack(side="left", padx=3)
        ttk.Button(sm_row, text="Redo PACE", command=lambda: self._reestablish(MODE_PACE)).pack(side="left", padx=3)
        self._sm_status = tk.StringVar()
        ttk.Label(sm_row, textvariable=self._sm_status, foreground="#333333").pack(side="left", padx=(12, 4))

        # ── Response ─────────────────────────────────────────────────────────
        resp_frame = ttk.LabelFrame(frame, text=" Response ", padding=10)
        resp_frame.pack(fill="both", expand=True, padx=5, pady=8)

        resp_row = ttk.Frame(resp_frame)
        resp_row.pack(fill="x", pady=3)

        ttk.Label(resp_row, text="Data:").pack(side="left", padx=(8, 2))
        self._resp_data = tk.StringVar()
        ttk.Entry(resp_row, textvariable=self._resp_data, width=70, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ttk.Label(resp_row, text="SW1:").pack(side="left", padx=(8, 2))
        self._resp_sw1 = tk.StringVar()
        ttk.Entry(resp_row, textvariable=self._resp_sw1, width=4, state="readonly").pack(side="left")
        ttk.Label(resp_row, text="SW2:").pack(side="left", padx=(8, 2))
        self._resp_sw2 = tk.StringVar()
        ttk.Entry(resp_row, textvariable=self._resp_sw2, width=4, state="readonly").pack(side="left", padx=(0, 8))

        # Plain-language meaning of the returned status word, shown under the
        # fields so an error code such as 6882 reads as something actionable.
        self._resp_status = tk.StringVar(value=_RESP_STATUS_HINT)
        ttk.Label(resp_frame, textvariable=self._resp_status, foreground="#555555").pack(
            anchor="w", padx=8, pady=(4, 0)
        )

        # Coloured hex dump of the response, sharing Traffic's renderer.
        dump_head = ttk.Frame(resp_frame)
        dump_head.pack(fill="x", pady=(6, 2))
        legend = build_legend(dump_head)
        legend.pack(side="left")
        # "Send to Comparer" stays disabled until a Comparer pane exists and the
        # tab has a response to send — mirroring the Traffic tab's guard.
        self._comparer_btn = ttk.Button(
            dump_head, text="Send to Comparer", command=self._send_to_comparer, state="disabled",
        )
        self._comparer_btn.pack(side="right", padx=4)

        self._resp_dump = HexDumpView(resp_frame, height=8)
        self._resp_dump.pack(fill="both", expand=True)

        # Keep a reference on root for TrafficPane to find
        self.root.forge_pane = self

        # Paint the initial (empty) tab.
        self._render_tabstrip()
        self._load_active()
        self._update_sm_status()

        # Re-sync the SM default whenever the Forge tab becomes visible, so a
        # passport read on the View tab is reflected here without a reload.
        self.root.main_notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed, add="+")

    # ── Request tabs ────────────────────────────────────────────────────────
    def _render_tabstrip(self):
        """Redraw the numbered tab buttons, highlighting the active one."""
        for w in self._tabstrip.winfo_children():
            w.destroy()
        for i in range(len(self._requests)):
            active = (i == self._active)
            tk.Button(
                self._tabstrip, text="#%d" % (i + 1),
                relief="sunken" if active else "raised",
                takefocus=0, padx=6, pady=1,
                command=lambda idx=i: self._select_request(idx),
            ).pack(side="left", padx=1)

    def _commit_active(self):
        """Save the on-screen request back into the active tab's model."""
        req = self._requests[self._active]
        req.raw_mode = self._raw_mode.get()
        if req.raw_mode:
            # Keep the model's fields consistent with the raw text when it
            # parses; if it is malformed, leave the last good fields in place.
            try:
                f = parse_apdu(self._raw.get())
            except ValueError:
                return
            req.cla, req.ins, req.p1, req.p2 = f["cla"], f["ins"], f["p1"], f["p2"]
            req.lc, req.data, req.le = f["lc"], f["data"], f["le"]
        else:
            req.cla = self._cla.get()
            req.ins = self._ins.get()
            req.p1 = self._p1.get()
            req.p2 = self._p2.get()
            req.lc = self._lc.get()
            req.data = self._data.get()
            req.le = self._le.get()

    def _load_active(self):
        """Populate the form and response area from the active tab's model."""
        req = self._requests[self._active]
        self._cla.set(req.cla)
        self._ins.set(req.ins)
        self._p1.set(req.p1)
        self._p2.set(req.p2)
        self._lc.set(req.lc)
        self._data.set(req.data)
        self._le.set(req.le)
        self._raw.set(assemble_apdu(req.cla, req.ins, req.p1, req.p2, req.lc, req.data, req.le))
        self._raw_mode.set(req.raw_mode)
        self._preset_var.set(_PRESET_PLACEHOLDER)
        self._apply_raw_visibility(req.raw_mode)

        self._resp_data.set(req.resp_data)
        self._resp_sw1.set("" if req.resp_sw1 is None else "%02X" % req.resp_sw1)
        self._resp_sw2.set("" if req.resp_sw2 is None else "%02X" % req.resp_sw2)
        self._resp_status.set(req.resp_status)
        self._render_response_dump(req)
        self._update_comparer_button(req)

    def _select_request(self, idx):
        if idx == self._active:
            return
        self._commit_active()
        self._active = idx
        self._render_tabstrip()
        self._load_active()

    def _add_request(self, req=None):
        """Append a new request tab (optionally pre-filled) and select it."""
        self._commit_active()
        if req is None:
            req = _ForgeRequest()
        self._requests.append(req)
        if len(self._requests) > _MAX_REQUESTS:
            self._requests = self._requests[-_MAX_REQUESTS:]
        self._active = len(self._requests) - 1
        self._render_tabstrip()
        self._load_active()

    def _close_request(self):
        """Close the active tab; the last remaining tab is reset, not removed."""
        if len(self._requests) == 1:
            self._requests[0] = _ForgeRequest()
            self._load_active()
            return
        del self._requests[self._active]
        if self._active >= len(self._requests):
            self._active = len(self._requests) - 1
        self._render_tabstrip()
        self._load_active()

    def load_transaction(self, tx):
        """Open a new tab populated from an APDUTransaction (Traffic → Forge)."""
        req = _ForgeRequest(
            cla=tx.request_cla, ins=tx.request_ins, p1=tx.request_p1, p2=tx.request_p2,
            lc=tx.request_lc, data=tx.request_data,
            # Leave LE empty so it is recomputed at send time.
            le="",
        )
        self._add_request(req)
        self._sync_sm_default()
        self._update_sm_status()

    # ── Raw / fielded toggle ──────────────────────────────────────────────────
    def _apply_raw_visibility(self, raw_mode):
        """Show the raw entry or the fielded rows, never both."""
        self._fields_row.pack_forget()
        self._data_row.pack_forget()
        self._raw_row.pack_forget()
        if raw_mode:
            self._raw_row.pack(fill="x", pady=3, before=self._sm_row)
        else:
            self._fields_row.pack(fill="x", pady=3, before=self._sm_row)
            self._data_row.pack(fill="x", pady=3, before=self._sm_row)

    def _toggle_raw(self):
        """Convert between the fielded and raw views when the box is ticked."""
        raw_mode = self._raw_mode.get()
        if raw_mode:
            # fielded → raw: assemble the current fields into the raw box.
            self._raw.set(assemble_apdu(
                self._cla.get(), self._ins.get(), self._p1.get(), self._p2.get(),
                self._lc.get(), self._data.get(), self._le.get(),
            ))
        else:
            # raw → fielded: parse the raw box back into the fields.
            try:
                f = parse_apdu(self._raw.get())
            except ValueError as e:
                messagebox.showerror("Invalid APDU", str(e))
                self._raw_mode.set(True)  # stay in raw mode so nothing is lost
                return
            self._cla.set(f["cla"])
            self._ins.set(f["ins"])
            self._p1.set(f["p1"])
            self._p2.set(f["p2"])
            self._lc.set(f["lc"])
            self._data.set(f["data"])
            self._le.set(f["le"])
        self._apply_raw_visibility(raw_mode)

    def _current_fields(self):
        """Return (cla, ins, p1, p2, lc, data, le) for the active view.

        In raw mode the hex box is the source of truth and is parsed here (also
        refreshing the fielded entries so the two views stay in step); in
        fielded mode the entries are read directly. Raises ValueError on a bad
        raw string.
        """
        if self._raw_mode.get():
            f = parse_apdu(self._raw.get())
            self._cla.set(f["cla"])
            self._ins.set(f["ins"])
            self._p1.set(f["p1"])
            self._p2.set(f["p2"])
            self._lc.set(f["lc"])
            self._data.set(f["data"])
            self._le.set(f["le"])
            return f["cla"], f["ins"], f["p1"], f["p2"], f["lc"], f["data"], f["le"]
        return (
            self._cla.get().strip(), self._ins.get().strip(),
            self._p1.get().strip(), self._p2.get().strip(),
            self._lc.get().strip(), self._data.get().strip(), self._le.get().strip(),
        )

    # ── Request presets ───────────────────────────────────────────────────────
    def _on_preset_selected(self, _event=None):
        """Fill the request fields from the chosen common-request template."""
        preset = _REQUEST_PRESETS.get(self._preset_var.get())
        if preset is None:
            return
        fields = {**_PRESET_DEFAULTS, **preset}
        self._cla.set(fields["cla"])
        self._ins.set(fields["ins"])
        self._p1.set(fields["p1"])
        self._p2.set(fields["p2"])
        self._lc.set(fields["lc"])
        self._data.set(fields["data"])
        self._le.set(fields["le"])
        if self._raw_mode.get():
            # Keep the raw box in step with the freshly-filled fields.
            self._raw.set(assemble_apdu(
                fields["cla"], fields["ins"], fields["p1"], fields["p2"],
                fields["lc"], fields["data"], fields["le"],
            ))

    # ── Secure Messaging selector ─────────────────────────────────────────────
    def _active_ciphering(self):
        iso = self.parent.iso7816
        return iso.ciphering if iso else None

    def _active_sm_label(self):
        """Label for the currently installed SM channel, or None if plaintext."""
        ciphering = self._active_ciphering()
        if not ciphering:
            return None
        return "AES (active)" if "Aes" in type(ciphering).__name__ else "3DES (active)"

    def _refresh_sm_options(self):
        """Keep the dropdown's option list in step with the active SM channel."""
        label = self._active_sm_label()
        self._sm_combo["values"] = [label, "None"] if label else ["None"]

    def _sync_sm_default(self):
        """Reset the selection to the active SM (unless the user forced None)."""
        label = self._active_sm_label()
        if label:
            self._sm_combo["values"] = [label, "None"]
            self._sm_var.set("None" if self._sm_user_forced_none else label)
        else:
            self._sm_combo["values"] = ["None"]
            self._sm_var.set("None")

    def _on_sm_choice(self, _event=None):
        self._sm_user_forced_none = (
            self._sm_var.get() == "None" and self._active_sm_label() is not None
        )

    def _on_tab_changed(self, _event=None):
        if self.root.main_notebook.select() == str(self.root.forge_tab):
            self._sync_sm_default()
            self._update_sm_status()

    def _update_sm_status(self):
        """Refresh the one-line summary of the active SM channel."""
        label = self._active_sm_label()
        self._sm_status.set(f"Secure messaging: {label}" if label else "Secure messaging: none (plaintext)")

    # ── Response rendering ─────────────────────────────────────────────────────
    def _response_segments(self, req):
        segs = []
        if req.resp_data:
            segs.append(("DATA", req.resp_data))
        if req.resp_sw1 is not None:
            segs.append(("SW1", "%02X" % req.resp_sw1))
        if req.resp_sw2 is not None:
            segs.append(("SW2", "%02X" % req.resp_sw2))
        return segs

    def _render_response_dump(self, req):
        segs = self._response_segments(req)
        if segs:
            self._resp_dump.render(segs)
        else:
            self._resp_dump.clear(_RESP_DUMP_HINT)

    def _update_comparer_button(self, req):
        has_comparer = hasattr(self.root, "comparer_pane")
        ready = has_comparer and req.last_tx is not None
        self._comparer_btn.configure(state="normal" if ready else "disabled")

    def _send_to_comparer(self):
        req = self._requests[self._active]
        if req.last_tx is None or not hasattr(self.root, "comparer_pane"):
            return
        self.root.comparer_pane.load_transactions([req.last_tx])
        notebook = self.root.main_notebook
        notebook.select(notebook.index(self.root.comparer_tab))

    # ── Secure messaging session (reset / re-establish) ───────────────────────
    def _reset_card(self):
        """Reconnect to the card and drop any Secure Messaging channel."""
        if not self._get_ready():
            return
        try:
            self.parent.iso7816.rstConnectionRaw()
            logging.info("Forge: reset card connection; secure messaging cleared.")
        except Exception as e:
            logging.exception("Forge: card reset failed")
            messagebox.showerror("Reset failed", str(e))
        finally:
            self._sm_user_forced_none = False
            self._sync_sm_default()
            self._update_sm_status()

    def _reestablish(self, mode):
        """Reset the card, then re-run BAC or PACE to build a fresh SM channel.

        Reads the MRZ (Number / DoB / Expiry) and optional CAN from the top of
        the window, exactly like the View tab's Read button, so recovering a
        wedged channel needs no re-typing.
        """
        if not self._get_ready():
            return
        iso = self.parent.iso7816
        try:
            doc_number = self.parent.doc_number.get().strip()
            dob = self.parent.dob.get().strip()
            expiry = self.parent.expiry.get().strip()
            can = self.parent.can.get().strip() or None

            build_mrz = None
            if doc_number and dob and expiry:
                build_mrz = MRZ((doc_number, dob, expiry))
                if not build_mrz.checkMRZ():
                    messagebox.showerror(
                        "Invalid MRZ",
                        "The Number / Date of Birth / Expiry at the top of the "
                        "window do not form a valid MRZ.",
                    )
                    return

            if mode == MODE_BAC and build_mrz is None:
                messagebox.showerror(
                    "MRZ required",
                    "BAC needs the Number, Date of Birth and Expiry fields filled in.",
                )
                return
            if mode == MODE_PACE and build_mrz is None and can is None:
                messagebox.showerror(
                    "Credentials required",
                    "PACE needs either a full MRZ or a CAN.",
                )
                return

            # Start from a clean card so a stale SSC can't poison the new
            # handshake, then run the chosen mechanism. The negotiator installs
            # the fresh SM channel on iso7816 and selects the eMRTD application.
            iso.rstConnectionRaw()
            result = AccessControlNegotiator(iso).open(build_mrz, mode=mode, can=can)
            logging.info(f"Forge: re-established secure messaging via {result.mechanism}.")
            messagebox.showinfo(
                "Secure messaging",
                f"Secure messaging re-established via {result.mechanism}.",
            )
        except AccessControlNegotiationError as e:
            logging.error(f"Forge: re-establishing secure messaging failed: {e}")
            messagebox.showerror("Secure messaging failed", str(e))
        except Exception as e:
            logging.exception("Forge: unexpected error re-establishing secure messaging")
            messagebox.showerror("Secure messaging failed", str(e))
        finally:
            self._sm_user_forced_none = False
            self._sync_sm_default()
            self._update_sm_status()

    def _get_ready(self):
        if not self.parent.reader:
            self.parent.get_reader()
        if not self.parent.reader:
            messagebox.showerror(
                "Reader missing",
                "Make sure you have the reader connected and the PCSC service running.",
            )
            return False
        if not self.parent.iso7816:
            self.parent.iso7816 = ISO7816(self.parent.reader)
        return True

    def _send(self):
        if not self._get_ready():
            return
        try:
            try:
                cla, ins, p1, p2, lc, data, le = self._current_fields()
            except ValueError as e:
                messagebox.showerror("Invalid APDU", str(e))
                return

            cla = cla.strip() or "00"
            ins = ins.strip() or "00"
            p1 = p1.strip() or "00"
            p2 = p2.strip() or "00"
            lc = lc.strip()
            data = data.strip()
            le = le.strip()

            if not lc and data:
                lc = "%02x" % (len(data) // 2)
            # An empty LE means "let me figure it out": request the maximum
            # available (Le=00). A value typed by the user is sent verbatim,
            # even if it turns out to be wrong.
            if not le:
                le = "00"

            cmd = APDUCommand(cla, ins, p1, p2, lc, data, le)

            iso = self.parent.iso7816
            saved_ciphering = iso.ciphering
            force_none = (self._sm_var.get() == "None")
            if force_none and saved_ciphering:
                # Bypass SM for this one APDU only — the SSC is left untouched.
                iso.ciphering = False
            try:
                resp = iso.transmit(cmd, "Forge APDU", full=True, source="forge")
            finally:
                # Restore the shared SM channel so its SSC counter survives a
                # one-off plaintext send and the View tab keeps working.
                iso.ciphering = saved_ciphering

            # Record the response on the active tab so it survives tab switches.
            req = self._requests[self._active]
            req.resp_data = toHexString(resp.data) if resp.data else ""
            req.resp_sw1 = resp.sw1
            req.resp_sw2 = resp.sw2
            req.resp_status = f"{APDUResponse.describe(resp.sw1, resp.sw2)} ({resp.sw1:02X}{resp.sw2:02X})"
            history = APDUHistory.get()
            req.last_tx = history[-1] if len(history) else None

            self._resp_data.set(req.resp_data)
            self._resp_sw1.set("%02X" % resp.sw1)
            self._resp_sw2.set("%02X" % resp.sw2)
            self._resp_status.set(req.resp_status)
            self._render_response_dump(req)
            self._update_comparer_button(req)

            sm_used = "none" if force_none or not saved_ciphering else self._active_sm_label()
            logging.info(
                f"FORGE REQUEST: CLA:{cla} INS:{ins} P1:{p1} P2:{p2} LC:{lc} DATA:{data} LE:{le} SM:{sm_used}\n"
                f"FORGE RESPONSE: Data:{toHexString(resp.data) if resp.data else ''} "
                f"SW1:{hex(resp.sw1)} SW2:{hex(resp.sw2)}"
            )
        except Exception as e:
            messagebox.showerror("Forge error", str(e))
        finally:
            self._sync_sm_default()
            self._update_sm_status()
