import tkinter as tk
from tkinter import ttk, simpledialog

from pypassport.apdu_history import APDUHistory
from pypassport.iso7816 import APDUCommand, APDUResponse
from pypassport.doc9303 import converter


# ── Column layout for the transaction list ───────────────────────────────────
_COLUMNS = (
    ("id",      "ID",        45,  False),
    ("time",    "Time",      80,  False),
    ("dir",     "Direction", 60,  False),
    ("info",    "Info",      300, True),
    ("sm",      "SM",        55,  False),
    ("source",  "Source",    70,  False),
    ("comment", "Comment",   160, True),
)


# ── Highlight palette for per-transaction annotations ────────────────────────
# Burp-style soft highlight colours; the label is what the context menu shows.
_HIGHLIGHTS = (
    ("Red",    "#ffd6d6"),
    ("Orange", "#ffe3c2"),
    ("Yellow", "#fff7c2"),
    ("Green",  "#d6f5d6"),
    ("Blue",   "#d6e8ff"),
    ("Purple", "#ecd6ff"),
)

# Marker for "All sources" in the source filter dropdown.
_SOURCE_ANY = "All sources"


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


# ── Clipboard formatters ─────────────────────────────────────────────────────
def _command_hex(tx):
    """The full command APDU as one contiguous uppercase hex string."""
    parts = (tx.request_cla, tx.request_ins, tx.request_p1, tx.request_p2,
             tx.request_lc, tx.request_data, tx.request_le)
    return "".join(p for p in parts if p).upper()


def _response_hex(tx):
    """The response data followed by its two status-word bytes."""
    return f"{(tx.response_data or '').upper()}{tx.response_sw1:02X}{tx.response_sw2:02X}"


def _python_command(tx):
    """A paste-ready APDUCommand(...) constructor call mirroring the request."""
    args = ", ".join(
        '"%s"' % v.upper() for v in (
            tx.request_cla, tx.request_ins, tx.request_p1, tx.request_p2,
            tx.request_lc, tx.request_data, tx.request_le,
        )
    )
    return f"APDUCommand({args})"


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

        # ── Filter / search bar ──────────────────────────────────────────────
        # Purely a view filter: it changes which recorded transactions are shown
        # but never touches the history itself. Any change re-renders the list.
        filter_bar = ttk.Frame(frame)
        filter_bar.pack(fill="x", padx=5, pady=(0, 5))

        ttk.Label(filter_bar, text="Filter:").pack(side="left", padx=(0, 3))
        self._filter_text = tk.StringVar()
        self._filter_text.trace_add("write", lambda *_: self._rebuild_tree())
        ttk.Entry(filter_bar, textvariable=self._filter_text, width=28).pack(side="left", padx=(0, 4))
        ttk.Button(filter_bar, text="✕", width=2,
                   command=lambda: self._filter_text.set("")).pack(side="left", padx=(0, 12))

        self._errors_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_bar, text="Errors only", variable=self._errors_only,
                        command=self._rebuild_tree).pack(side="left", padx=4)
        self._hide_sm = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_bar, text="Hide SM", variable=self._hide_sm,
                        command=self._rebuild_tree).pack(side="left", padx=4)

        ttk.Label(filter_bar, text="Source:").pack(side="left", padx=(12, 3))
        self._source_filter = tk.StringVar(value=_SOURCE_ANY)
        self._source_combo = ttk.Combobox(
            filter_bar, textvariable=self._source_filter, state="readonly", width=12,
            values=[_SOURCE_ANY], postcommand=self._refresh_source_options,
        )
        self._source_combo.pack(side="left")
        self._source_combo.bind("<<ComboboxSelected>>", lambda _e: self._rebuild_tree())

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

        # Wire-vs-cleartext toggle. The dump defaults to the decoded (cleartext)
        # APDU; flipping this shows the bytes actually exchanged over PC/SC,
        # which for an SM session are the protected 87/97/8E DOs. The toggle
        # stays disabled until the selected row carries wire data (see
        # _wire_available).
        self._show_wire = tk.BooleanVar(value=False)
        self._wire_toggle = ttk.Checkbutton(
            legend, text="Show wire (encrypted) bytes",
            variable=self._show_wire, command=self._refresh_dump, state="disabled",
        )
        self._wire_toggle.pack(side="right", padx=4)

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
        # One Treeview tag per highlight colour; a user-set colour overrides the
        # default ok/err backgrounds on both rows of a transaction.
        for _label, color in _HIGHLIGHTS:
            self._tree.tag_configure(self._color_tag(color), background=color)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Button-3>", self._on_right_click)

        # ── Right-click context menu ─────────────────────────────────────────
        self._menu = self._build_context_menu()

        # Populate with any already-recorded transactions.
        self._rebuild_tree()

    # ── Row rendering ─────────────────────────────────────────────────────────
    @staticmethod
    def _color_tag(color):
        return f"hl_{color.lstrip('#')}"

    def _row_tags(self, tx):
        """(request tags, response tags) — a user colour overrides ok/err."""
        if tx.color:
            color_tag = self._color_tag(tx.color)
            # Configure on demand so colours restored from a saved session still
            # render even if they aren't in the built-in palette.
            self._tree.tag_configure(color_tag, background=tx.color)
            return ("req", color_tag), (color_tag,)
        is_error = (tx.response_sw1, tx.response_sw2) != (0x90, 0x00)
        return ("req",), ("resp_err" if is_error else "resp_ok",)

    def _append_transaction(self, idx, tx):
        # View filter is applied here so it works identically for the initial
        # rebuild and for transactions arriving live; history is never touched.
        if not self._matches_filter(tx):
            return

        sm_label = tx.sm_type if tx.sm_active else "—"
        time_str = tx.timestamp.strftime("%H:%M:%S")
        req_tags, resp_tags = self._row_tags(tx)

        self._tree.insert("", "end", iid=f"{idx}-req", tags=req_tags, values=(
            idx + 1, time_str, "→ Req", _request_info(tx), sm_label, tx.source, tx.comment,
        ))
        # Each request has exactly one response, so the response row repeats no
        # metadata: ID, time, SM, source and comment are left to the request row.
        self._tree.insert("", "end", iid=f"{idx}-resp", tags=resp_tags, values=(
            "", "", "← Res", _response_info(tx), "", "", "",
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

    # ── View filter ────────────────────────────────────────────────────────────
    def _matches_filter(self, tx):
        if self._errors_only.get() and (tx.response_sw1, tx.response_sw2) == (0x90, 0x00):
            return False
        if self._hide_sm.get() and tx.sm_active:
            return False
        source = self._source_filter.get()
        if source != _SOURCE_ANY and tx.source != source:
            return False
        needle = self._filter_text.get().strip().lower()
        if needle:
            haystack = f"{_request_info(tx)} {_response_info(tx)} {tx.comment}".lower()
            if needle not in haystack:
                return False
        return True

    def _refresh_source_options(self):
        """Offer every source present in the history, plus 'All sources'."""
        seen = []
        for tx in self._history:
            if tx.source and tx.source not in seen:
                seen.append(tx.source)
        self._source_combo["values"] = [_SOURCE_ANY] + seen

    # ── Hex dump ──────────────────────────────────────────────────────────────
    def _wire_available(self, tx, direction):
        """Whether on-the-wire bytes were captured for this row.

        ISO7816.transmit records the exact frame sent and the raw response
        received before unprotect. For an SM session these differ from the
        cleartext APDU; for a plaintext session they match it. A row only
        unlocks the wire toggle once it actually carries these bytes.
        """
        attr = "wire_request_hex" if direction == "req" else "wire_response_hex"
        return bool(getattr(tx, attr, None))

    def _segments(self, tx, direction, wire=False):
        """Return [(field, hexstring), …] for the chosen direction."""
        if wire:
            attr = "wire_request_hex" if direction == "req" else "wire_response_hex"
            return [("DATA", getattr(tx, attr, "") or "")]
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
        wire = self._show_wire.get() and self._wire_available(tx, direction)
        # Flatten every field into a (byte, field) list so each byte keeps its tag.
        flat = []
        for field, hexstr in self._segments(tx, direction, wire=wire):
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
        self._current = None
        self._wire_toggle.configure(state="disabled")
        self._dump.delete("1.0", "end")
        self._dump.insert("end", "Select a request or response above to inspect its bytes.",
                         ("offset",))

    def _on_select(self, _event=None):
        selected = self._tree.selection()
        if not selected:
            self._clear_dump()
            return
        idx_str, direction = selected[-1].rsplit("-", 1)
        self._current = (int(idx_str), direction)
        # Unlock the wire toggle only when this row actually has wire bytes.
        tx = self._history[self._current[0]]
        self._wire_toggle.configure(
            state="normal" if self._wire_available(tx, direction) else "disabled"
        )
        self._refresh_dump()

    def _refresh_dump(self):
        """Re-render the current selection (e.g. after the wire toggle flips)."""
        if not self._current:
            return
        idx, direction = self._current
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

    # ── Context menu ────────────────────────────────────────────────────────────
    def _build_context_menu(self):
        menu = tk.Menu(self._tree, tearoff=0)
        menu.add_command(label="Send to Forge", command=self._send_to_forge)
        menu.add_command(label="Send to Decoder", command=self._send_to_decoder)
        menu.add_command(label="Send to Comparer", command=self._send_to_comparer)
        menu.add_separator()
        menu.add_command(label="Copy as hex", command=self._copy_as_hex)
        menu.add_command(label="Copy as Python (APDUCommand(...))",
                         command=self._copy_as_python)
        menu.add_separator()
        menu.add_command(label="Set comment…", command=self._set_comment)

        highlight = tk.Menu(menu, tearoff=0)
        for label, color in _HIGHLIGHTS:
            highlight.add_command(label=label, command=lambda c=color: self._set_color(c))
        highlight.add_separator()
        highlight.add_command(label="Clear highlight", command=lambda: self._set_color(""))
        menu.add_cascade(label="Highlight", menu=highlight)
        return menu

    def _on_right_click(self, event):
        row = self._tree.identify_row(event.y)
        if not row:
            return
        # Right-clicking outside the current selection narrows to that one row;
        # right-clicking within a multi-selection keeps it, so bulk copy works.
        if row not in self._tree.selection():
            self._tree.selection_set(row)
        self._tree.focus(row)
        # Comparer only becomes available once its pane is built (a later step).
        comparer_state = "normal" if hasattr(self.root, "comparer_pane") else "disabled"
        self._menu.entryconfigure("Send to Comparer", state=comparer_state)
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    # ── Annotations ──────────────────────────────────────────────────────────────
    def _annotate_index(self):
        """The single transaction the annotation acts on (the focused row)."""
        focused = self._tree.focus()
        if focused:
            return int(focused.rsplit("-", 1)[0])
        indices = self._selected_indices()
        return indices[0] if indices else None

    def _set_comment(self):
        idx = self._annotate_index()
        if idx is None:
            return
        tx = self._history[idx]
        comment = simpledialog.askstring(
            "Comment", "Note for this transaction:",
            initialvalue=tx.comment, parent=self.root,
        )
        if comment is None:  # dialog cancelled — leave the existing comment
            return
        tx.comment = comment
        self._refresh_row(idx)

    def _set_color(self, color):
        idx = self._annotate_index()
        if idx is None:
            return
        self._history[idx].color = color
        self._refresh_row(idx)

    def _refresh_row(self, idx):
        """Re-render one transaction in place, keeping its slot and selection.

        Updating the existing rows (rather than delete + re-insert) avoids any
        dependence on tree position, which would be wrong while a filter is
        hiding earlier transactions.
        """
        req_iid, resp_iid = f"{idx}-req", f"{idx}-resp"
        if not self._tree.exists(req_iid):
            return
        tx = self._history[idx]
        # A comment can be the reason a row currently matches a text filter;
        # if editing it drops the match, the row leaves the filtered view.
        if not self._matches_filter(tx):
            self._tree.delete(req_iid, resp_iid)
            self._clear_dump()
            return
        req_tags, resp_tags = self._row_tags(tx)
        self._tree.item(req_iid, tags=req_tags)
        self._tree.item(resp_iid, tags=resp_tags)
        self._tree.set(req_iid, "comment", tx.comment)

    # ── Send / copy actions ───────────────────────────────────────────────────────
    def _send_to_decoder(self):
        idx = self._annotate_index()
        if idx is None or not hasattr(self.root, "decoder_pane"):
            return
        tx = self._history[idx]
        self.root.decoder_pane.load_fields(_command_hex(tx), _response_hex(tx))

    def _send_to_comparer(self):
        indices = self._selected_indices()
        if not indices or not hasattr(self.root, "comparer_pane"):
            return
        self.root.comparer_pane.load_transactions(
            [self._history[i] for i in indices]
        )
        notebook = self.root.main_notebook
        notebook.select(notebook.index(self.root.comparer_tab))

    def _copy_to_clipboard(self, text):
        if not text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _copy_as_hex(self):
        # Honour each selected row's direction: request rows copy the command
        # bytes, response rows copy the response bytes (data + status word).
        lines = []
        for iid in self._tree.selection():
            idx_str, direction = iid.rsplit("-", 1)
            tx = self._history[int(idx_str)]
            lines.append(_command_hex(tx) if direction == "req" else _response_hex(tx))
        self._copy_to_clipboard("\n".join(lines))

    def _copy_as_python(self):
        lines = [_python_command(self._history[idx]) for idx in self._selected_indices()]
        self._copy_to_clipboard("\n".join(lines))
