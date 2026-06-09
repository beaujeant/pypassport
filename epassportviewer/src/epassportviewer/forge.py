import logging
import tkinter as tk
from tkinter import ttk, messagebox
from pypassport.iso7816 import ISO7816, APDUCommand
from pypassport.utils import toHexString


class ForgePane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root

        frame = self.root.forge_tab

        # ── Request ──────────────────────────────────────────────────────────
        req_frame = ttk.LabelFrame(frame, text=" Request ", padding=10)
        req_frame.pack(fill="x", padx=5, pady=8)

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

        self._sm_label = tk.StringVar(value="SM: —")
        ttk.Label(row3, textvariable=self._sm_label, foreground="gray").pack(side="left", padx=8)

        ttk.Button(row3, text="Send APDU", command=self._send).pack(side="right", padx=8)

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

        # Keep a reference on root for TrafficPane to find
        self.root.forge_pane = self

    def load_transaction(self, tx):
        """Populate the request form from an APDUTransaction (called from Traffic tab)."""
        self._cla.set(tx.request_cla)
        self._ins.set(tx.request_ins)
        self._p1.set(tx.request_p1)
        self._p2.set(tx.request_p2)
        self._lc.set(tx.request_lc)
        self._data.set(tx.request_data)
        self._le.set(tx.request_le)
        self._resp_data.set("")
        self._resp_sw1.set("")
        self._resp_sw2.set("")
        self._refresh_sm_label()

    def _refresh_sm_label(self):
        if self.parent.iso7816 and self.parent.iso7816.ciphering:
            sm_type = type(self.parent.iso7816.ciphering).__name__
            sm_label = "AES" if "Aes" in sm_type else "3DES"
            self._sm_label.set(f"SM: {sm_label} (active)")
        else:
            self._sm_label.set("SM: — (none)")

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
        self._refresh_sm_label()
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

            cmd = APDUCommand(cla, ins, p1, p2, lc, data, le)
            resp = self.parent.iso7816.transmit(cmd, "Forge APDU", full=True, source="forge")

            self._resp_data.set(toHexString(resp.data) if resp.data else "")
            self._resp_sw1.set("%02X" % resp.sw1)
            self._resp_sw2.set("%02X" % resp.sw2)

            logging.info(
                f"FORGE REQUEST: CLA:{cla} INS:{ins} P1:{p1} P2:{p2} LC:{lc} DATA:{data} LE:{le}\n"
                f"FORGE RESPONSE: Data:{toHexString(resp.data) if resp.data else ''} "
                f"SW1:{hex(resp.sw1)} SW2:{hex(resp.sw2)}"
            )
        except Exception as e:
            messagebox.showerror("Forge error", str(e))
