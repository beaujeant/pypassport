import tkinter as tk
from tkinter import ttk

from pypassport.apdu_history import APDUHistory
from pypassport.iso7816 import APDUCommand, APDUResponse
from pypassport.doc9303 import converter


# ── Column layout for the transaction list ───────────────────────────────────
_COLUMNS = (
    ("id",     "ID",        45,  False),
    ("time",   "Time",      80,  False),
    ("dir",    "Direction", 60,  False),
    ("info",   "Info",      320, True),
    ("sm",     "SM",        55,  False),
    ("source", "Source",    70,  False),
)


# ── Human-readable INS names ─────────────────────────────────────────────────
# Start from the dictionary already maintained on APDUCommand, then add the few
# extra instructions pypassport issues that aren't in that BAC-centric table.
_INS_NAMES = {code: name for name, code in APDUCommand.Instructions.items()}
_INS_NAMES.update({
    0x22: "MANAGE SECURITY ENVIRONMENT",
    0x86: "GENERAL AUTHENTICATE",
    0xC0: "GET RESPONSE",
    0xCA: "GET DATA",
})


# ── Per-field colours used by both the hex dump and its legend ───────────────
_FIELD_COLORS = {
    "CLA":  "#cfe8ff",
    "INS":  "#c8f7c5",
    "P1":   "#fff3bf",
    "P2":   "#ffe0b3",
    "LC":   "#ffd6e7",
    "DATA": "#e9ecef",
    "LE":   "#d0f0f0",
    "SW1":  "#ffc9c9",
    "SW2":  "#ff8787",
}
_LEGEND_ORDER = ("CLA", "INS", "P1", "P2", "LC", "DATA", "LE", "SW1", "SW2")


def _select_detail(p1, p2, data):
    """Best-effort description of a SELECT FILE target."""
    d = (data or "").upper()
    if not d:
        return None
    if d == "3F00":
        return "MF"
    if d.startswith("A0000002471001"):
        return "eMRTD AID"
    try:
        return converter.toEF(d)
    except KeyError:
        return d


def _request_info(tx):
    """Translate a command APDU header into a readable description."""
    try:
        ins = int(tx.request_ins, 16)
    except ValueError:
        ins = -1

    name = _INS_NAMES.get(ins)

    if name == "SELECT FILE":
        detail = _select_detail(tx.request_p1, tx.request_p2, tx.request_data)
        return f"SELECT FILE ({detail})" if detail else "SELECT FILE"

    if name == "READ BINARY":
        p1 = int(tx.request_p1, 16)
        if p1 & 0x80:  # short-EF identifier in P1
            return f"READ BINARY (SFID {p1 & 0x1F:02X}, offset {int(tx.request_p2, 16)})"
        return f"READ BINARY (offset {int(tx.request_p1 + tx.request_p2, 16)})"

    if name:
        return name

    # Unknown instruction — fall back to the raw header bytes.
    header = " ".join(
        v.upper() for v in (tx.request_cla, tx.request_ins, tx.request_p1, tx.request_p2)
    )
    return f"Unknown [{header}]"


def _status_text(sw1, sw2):
    return f"{APDUResponse.describe(sw1, sw2)} ({sw1:02X}{sw2:02X})"


def _response_info(tx):
    """Translate a response APDU: status word plus a short data preview."""
    status = _status_text(tx.response_sw1, tx.response_sw2)
    if tx.response_data:
        preview = tx.response_data[:16].upper()
        ellipsis = "…" if len(tx.response_data) > 16 else ""
        return f"{status} — {preview}{ellipsis}"
    return status


class TrafficPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self._history = APDUHistory.get()
        self._history.add_listener(self._on_new_transaction)

        frame = self.root.traffic_tab

        # ── Toolbar ──────────────────────────────────────────────────────────
        # Keep the safe action (Send to Forge) far from the destructive ones
        # (Delete / Clear) so they can't be hit by accident.
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=5, pady=5)
        ttk.Button(toolbar, text="Send to Forge", command=self._send_to_forge).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Clear all", command=self._clear_all).pack(side="right", padx=3)
        ttk.Separator(toolbar, orient="vertical").pack(side="right", fill="y", padx=12, pady=2)
        ttk.Button(toolbar, text="Delete selected", command=self._delete_selected).pack(side="right", padx=3)

        # ── Detail (hex dump) box, pinned to the bottom ──────────────────────
        detail_frame = ttk.LabelFrame(frame, text=" Selected transaction ", padding=6)
        detail_frame.pack(side="bottom", fill="x", padx=5, pady=(0, 5))

        legend = ttk.Frame(detail_frame)
        legend.pack(fill="x", pady=(0, 4))
        ttk.Label(legend, text="Fields:").pack(side="left", padx=(0, 4))
        for field in _LEGEND_ORDER:
            # Force solid black text: the default label foreground is a low
            # contrast grey that is hard to read on these pale swatch colours.
            tk.Label(
                legend, text=field, background=_FIELD_COLORS[field],
                foreground="#000000",
                padx=5, pady=1, relief="solid", borderwidth=1,
            ).pack(side="left", padx=2)

        dump_wrap = ttk.Frame(detail_frame)
        dump_wrap.pack(fill="x")
        # Kept in the normal state (not "disabled") so the text renders in solid
        # black; a disabled Text dims to a hard-to-read grey on some platforms.
        # Editing is blocked via _block_edit instead, while copy/select still work.
        self._dump = tk.Text(dump_wrap, height=10, font=("Courier", 10), wrap="none",
                             background="#fbfbfb", borderwidth=0, foreground="#000000")
        self._dump.bind("<Key>", self._block_edit)
        self._dump.bind("<<Paste>>", lambda e: "break")
        self._dump.bind("<Button-2>", lambda e: "break")
        dump_vsb = ttk.Scrollbar(dump_wrap, orient="vertical", command=self._dump.yview)
        self._dump.configure(yscrollcommand=dump_vsb.set)
        self._dump.pack(side="left", fill="both", expand=True)
        dump_vsb.pack(side="right", fill="y")

        self._dump.tag_configure("offset", foreground="#666666")
        for field, color in _FIELD_COLORS.items():
            self._dump.tag_configure(field, background=color)

        # ── Transaction list ─────────────────────────────────────────────────
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        cols = [c[0] for c in _COLUMNS]
        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        for col_id, heading, width, stretch in _COLUMNS:
            self._tree.heading(col_id, text=heading)
            self._tree.column(col_id, width=width, minwidth=width, stretch=stretch)

        self._tree.tag_configure("resp_ok", background="#f4fbf4")
        self._tree.tag_configure("resp_err", background="#fdeded")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Populate with any already-recorded transactions.
        self._rebuild_tree()

    # ── Row rendering ─────────────────────────────────────────────────────────
    def _append_transaction(self, idx, tx):
        sm_label = tx.sm_type if tx.sm_active else "—"
        time_str = tx.timestamp.strftime("%H:%M:%S")
        is_error = (tx.response_sw1, tx.response_sw2) != (0x90, 0x00)

        self._tree.insert("", "end", iid=f"{idx}-req", tags=("req",), values=(
            idx + 1, time_str, "→ Req", _request_info(tx), sm_label, tx.source,
        ))
        # Each request has exactly one response, so the response row repeats no
        # metadata: ID, time, SM and source are left to the request row above.
        self._tree.insert("", "end", iid=f"{idx}-resp",
                          tags=("resp_err" if is_error else "resp_ok",), values=(
            "", "", "← Res", _response_info(tx), "", "",
        ))

    def _rebuild_tree(self):
        self._tree.delete(*self._tree.get_children())
        for idx, tx in enumerate(self._history):
            self._append_transaction(idx, tx)
        self._clear_dump()

    def _on_new_transaction(self, tx):
        # Called from the pypassport thread — schedule on the Tk main thread.
        # Capture the history index now so it stays correct if records pile up.
        idx = len(self._history) - 1
        self.root.after(0, lambda: self._append_transaction(idx, tx))

    # ── Hex dump ──────────────────────────────────────────────────────────────
    def _segments(self, tx, direction):
        """Return [(field, hexstring), …] for the chosen direction."""
        if direction == "req":
            segs = [
                ("CLA", tx.request_cla), ("INS", tx.request_ins),
                ("P1", tx.request_p1), ("P2", tx.request_p2),
            ]
            if tx.request_lc:
                segs.append(("LC", tx.request_lc))
            if tx.request_data:
                segs.append(("DATA", tx.request_data))
            if tx.request_le:
                segs.append(("LE", tx.request_le))
            return segs

        segs = []
        if tx.response_data:
            segs.append(("DATA", tx.response_data))
        segs.append(("SW1", "%02X" % tx.response_sw1))
        segs.append(("SW2", "%02X" % tx.response_sw2))
        return segs

    def _render_dump(self, tx, direction):
        # Flatten every field into a (byte, field) list so each byte keeps its tag.
        flat = []
        for field, hexstr in self._segments(tx, direction):
            try:
                data = bytes.fromhex(hexstr)
            except ValueError:
                continue
            flat.extend((b, field) for b in data)

        self._dump.delete("1.0", "end")

        for off in range(0, len(flat), 16):
            chunk = flat[off:off + 16]
            self._dump.insert("end", "%08X  " % off, ("offset",))
            for i in range(16):
                if i == 8:
                    self._dump.insert("end", " ")
                if i < len(chunk):
                    b, field = chunk[i]
                    self._dump.insert("end", "%02X " % b, (field,))
                else:
                    self._dump.insert("end", "   ")
            self._dump.insert("end", " |")
            for b, field in chunk:
                ch = chr(b) if 32 <= b < 127 else "."
                self._dump.insert("end", ch, (field,))
            self._dump.insert("end", "|\n")

    def _block_edit(self, event):
        # Allow copy/select-all shortcuts and cursor movement; block edits.
        if event.state & 0x4 and event.keysym.lower() in ("c", "a"):
            return None
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End",
                             "Prior", "Next"):
            return None
        return "break"

    def _clear_dump(self):
        self._dump.delete("1.0", "end")
        self._dump.insert("end", "Select a request or response above to inspect its bytes.",
                         ("offset",))

    def _on_select(self, _event=None):
        selected = self._tree.selection()
        if not selected:
            self._clear_dump()
            return
        idx_str, direction = selected[-1].rsplit("-", 1)
        idx = int(idx_str)
        self._render_dump(self._history[idx], direction)

    # ── Toolbar actions ───────────────────────────────────────────────────────
    def _selected_indices(self):
        return sorted({int(iid.rsplit("-", 1)[0]) for iid in self._tree.selection()})

    def _delete_selected(self):
        indices = self._selected_indices()
        if not indices:
            return
        for idx in reversed(indices):  # high → low so indices stay valid
            self._history.delete(idx)
        self._rebuild_tree()

    def _clear_all(self):
        self._history.clear()
        self._rebuild_tree()

    def _send_to_forge(self):
        indices = self._selected_indices()
        if not indices:
            return
        tx = self._history[indices[0]]
        if hasattr(self.root, "forge_pane"):
            self.root.forge_pane.load_transaction(tx)
            notebook = self.root.main_notebook
            notebook.select(notebook.index(self.root.forge_tab))
