import logging
import tkinter as tk
from tkinter import ttk, messagebox
from pypassport.iso7816 import ISO7816, APDUCommand, APDUResponse
from pypassport.utils import toHexString
from pypassport.doc9303.mrz import MRZ
from pypassport.doc9303.access_control import (
    AccessControlNegotiator,
    AccessControlNegotiationError,
    MODE_BAC,
    MODE_PACE,
)


# Common request templates, mirroring the buttons under Custom > Requests.
# Selecting one fills the request header fields below; any field a preset
# omits falls back to _PRESET_DEFAULTS.
_PRESET_PLACEHOLDER = "Common requests…"
_RESP_STATUS_HINT = "Send a request to see the status-word translation here."
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


class ForgePane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root

        # Set to True once the user explicitly forces "None" while an SM
        # channel is active, so the default selection stops snapping back to
        # the active SM on every refresh.
        self._sm_user_forced_none = False

        frame = self.root.forge_tab

        # ── Request ──────────────────────────────────────────────────────────
        req_frame = ttk.LabelFrame(frame, text=" Request ", padding=10)
        req_frame.pack(fill="x", padx=5, pady=8)

        # Preset selector: pick a common request and have its header bytes
        # filled into the fields below (same set as Custom > Requests).
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

        row1 = ttk.Frame(req_frame)
        row1.pack(fill="x", pady=3)

        for label, width, attr in (
            ("CLA", 3, "cla"),
            ("INS", 3, "ins"),
            ("P1",  3, "p1"),
            ("P2",  3, "p2"),
            ("LC",  4, "lc"),
            ("LE",  4, "le"),
        ):
            ttk.Label(row1, text=f"{label}:").pack(side="left", padx=(8, 2))
            var = tk.StringVar()
            setattr(self, f"_{attr}", var)
            ttk.Entry(row1, textvariable=var, width=width).pack(side="left")

        row2 = ttk.Frame(req_frame)
        row2.pack(fill="x", pady=3)
        ttk.Label(row2, text="DATA:").pack(side="left", padx=(8, 2))
        self._data = tk.StringVar()
        ttk.Entry(row2, textvariable=self._data, width=80).pack(side="left", fill="x", expand=True, padx=(0, 8))

        row3 = ttk.Frame(req_frame)
        row3.pack(fill="x", pady=5)

        # SM selector. Defaults to whatever Secure Messaging channel is already
        # in place (BAC/PACE), so sends are encrypted transparently. The user
        # can force "None" to send a single plaintext APDU without tearing down
        # the shared channel.
        ttk.Label(row3, text="SM:").pack(side="left", padx=(8, 2))
        self._sm_var = tk.StringVar(value="None")
        self._sm_combo = ttk.Combobox(
            row3, textvariable=self._sm_var, state="readonly", width=14,
            values=["None"], postcommand=self._refresh_sm_options,
        )
        self._sm_combo.pack(side="left")
        self._sm_combo.bind("<<ComboboxSelected>>", self._on_sm_choice)

        ttk.Button(row3, text="Send APDU", command=self._send).pack(side="right", padx=8)

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
        resp_frame.pack(fill="x", padx=5, pady=8)

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

        # Keep a reference on root for TrafficPane to find
        self.root.forge_pane = self
        self._update_sm_status()

        # Re-sync the SM default whenever the Forge tab becomes visible, so a
        # passport read on the View tab is reflected here without a reload.
        self.root.main_notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed, add="+")

    def load_transaction(self, tx):
        """Populate the request form from an APDUTransaction (called from Traffic tab)."""
        self._cla.set(tx.request_cla)
        self._ins.set(tx.request_ins)
        self._p1.set(tx.request_p1)
        self._p2.set(tx.request_p2)
        self._lc.set(tx.request_lc)
        self._data.set(tx.request_data)
        # Leave LE empty so it is recomputed at send time.
        self._le.set("")
        self._resp_data.set("")
        self._resp_sw1.set("")
        self._resp_sw2.set("")
        self._resp_status.set(_RESP_STATUS_HINT)
        self._preset_var.set(_PRESET_PLACEHOLDER)
        self._sync_sm_default()

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
            cla  = self._cla.get().strip() or "00"
            ins  = self._ins.get().strip() or "00"
            p1   = self._p1.get().strip() or "00"
            p2   = self._p2.get().strip() or "00"
            lc   = self._lc.get().strip()
            data = self._data.get().strip()
            le   = self._le.get().strip()

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

            self._resp_data.set(toHexString(resp.data) if resp.data else "")
            self._resp_sw1.set("%02X" % resp.sw1)
            self._resp_sw2.set("%02X" % resp.sw2)
            self._resp_status.set(
                f"{APDUResponse.describe(resp.sw1, resp.sw2)} ({resp.sw1:02X}{resp.sw2:02X})"
            )

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
