from tkinter import ttk
from pypassport.apdu_history import APDUHistory


_COLUMNS = (
    ("#",      "#",      40),
    ("time",   "Time",   70),
    ("cla",    "CLA",    36),
    ("ins",    "INS",    36),
    ("p1",     "P1",     36),
    ("p2",     "P2",     36),
    ("lc",     "LC",     36),
    ("data",   "Req Data", 130),
    ("le",     "LE",     36),
    ("sm",     "SM",     60),
    ("rdata",  "Resp Data", 130),
    ("sw1",    "SW1",    40),
    ("sw2",    "SW2",    40),
    ("source", "Source", 60),
)


class TrafficPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self._history = APDUHistory.get()
        self._history.add_listener(self._on_new_transaction)

        frame = self.root.traffic_tab

        # Toolbar
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=5, pady=5)
        ttk.Button(toolbar, text="Delete selected", command=self._delete_selected).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Clear all", command=self._clear_all).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Send to Forge", command=self._send_to_forge).pack(side="left", padx=3)

        # Treeview
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        cols = [c[0] for c in _COLUMNS]
        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")

        for col_id, heading, width in _COLUMNS:
            self._tree.heading(col_id, text=heading)
            self._tree.column(col_id, width=width, minwidth=width, stretch=(col_id in ("data", "rdata")))

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # Populate with any already-recorded transactions (e.g. replayed on re-open)
        for tx in self._history:
            self._append_row(tx)

    def _append_row(self, tx):
        idx = len(self._tree.get_children())
        sm_label = tx.sm_type if tx.sm_active else "—"
        time_str = tx.timestamp.strftime("%H:%M:%S")
        req_data = tx.request_data[:40] + ("…" if len(tx.request_data) > 40 else "")
        resp_data = tx.response_data[:40] + ("…" if len(tx.response_data) > 40 else "")
        sw1 = "%02X" % tx.response_sw1
        sw2 = "%02X" % tx.response_sw2
        self._tree.insert("", "end", iid=str(idx), values=(
            idx + 1,
            time_str,
            tx.request_cla.upper(),
            tx.request_ins.upper(),
            tx.request_p1.upper(),
            tx.request_p2.upper(),
            tx.request_lc.upper() if tx.request_lc else "—",
            req_data.upper() if req_data else "—",
            tx.request_le.upper() if tx.request_le else "—",
            sm_label,
            resp_data.upper() if resp_data else "—",
            sw1,
            sw2,
            tx.source,
        ))

    def _on_new_transaction(self, tx):
        # Called from pypassport thread — schedule on the Tk main thread
        self.root.after(0, lambda: self._append_row(tx))

    def _delete_selected(self):
        selected = self._tree.selection()
        if not selected:
            return
        # Convert iid→list index, delete from highest to lowest so indices stay valid
        indices = sorted([int(iid) for iid in selected], reverse=True)
        for idx in indices:
            self._history.delete(idx)
        self._rebuild_tree()

    def _clear_all(self):
        self._history.clear()
        self._rebuild_tree()

    def _rebuild_tree(self):
        self._tree.delete(*self._tree.get_children())
        for tx in self._history:
            self._append_row(tx)

    def _send_to_forge(self):
        selected = self._tree.selection()
        if not selected:
            return
        # Use the first selected item
        idx = int(selected[0])
        tx = self._history[idx]
        if hasattr(self.root, "forge_pane"):
            self.root.forge_pane.load_transaction(tx)
            # Switch to the Forge tab
            notebook = self.root.main_notebook
            forge_tab_idx = notebook.index(self.root.forge_tab)
            notebook.select(forge_tab_idx)
