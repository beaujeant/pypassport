"""Comparer tab — byte-level diff of two blobs.

Accepts two byte blobs from any of three sources:

* a Traffic or Forge right-click ("Send to Comparer"), which loads the
  transaction's response bytes;
* a file on disk (raw bytes, a hex-text dump, or a saved ``.epd`` snapshot —
  pick which EF to pull from);
* hex pasted straight into either input box.

It then shows an aligned hex diff with mismatching bytes highlighted, plus a
length / Hamming-distance summary.
"""

import json
import logging

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
except ImportError:  # headless (e.g. CI): the pure helpers below stay importable
    tk = ttk = filedialog = messagebox = simpledialog = None


# ── Pure helpers (no Tk) ──────────────────────────────────────────────────────
def parse_hex(text: str) -> bytes:
    """Parse a tolerant hex string into bytes.

    Whitespace (including newlines) and a leading ``0x`` are ignored. Raises
    ``ValueError`` on any non-hex character or an odd digit count.
    """
    cleaned = "".join(text.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError("hex string has an odd number of digits")
    return bytes.fromhex(cleaned)


def diff_summary(a: bytes, b: bytes) -> dict:
    """Compute a byte-level diff summary of two blobs.

    Returns a dict with the lengths, whether the blobs are identical, the
    overlapping (compared) length, the byte-level Hamming distance over that
    overlap, the count of trailing bytes only one side has, and the offset of
    the first difference (``None`` when identical).
    """
    overlap = min(len(a), len(b))
    mismatches = [i for i in range(overlap) if a[i] != b[i]]
    length_delta = abs(len(a) - len(b))
    if mismatches:
        first_diff = mismatches[0]
    elif length_delta:
        first_diff = overlap  # blobs agree on the overlap; first side runs out here
    else:
        first_diff = None
    return {
        "len_a": len(a),
        "len_b": len(b),
        "equal": a == b,
        "compared": overlap,
        "hamming": len(mismatches),
        "length_delta": length_delta,
        "first_diff": first_diff,
    }


def _ef_blobs_from_snapshot(data: dict) -> dict:
    """Collect ``{EF name: hex}`` entries from a parsed ``.epd`` snapshot."""
    blobs = {}
    for section in ("mf_ef_raw", "ef_raw"):
        for name, hex_str in (data.get(section) or {}).items():
            if hex_str:
                blobs[name] = hex_str
    return blobs


class ComparerPane:
    _A_HINT = "Paste hex here, load a file, or use “Send to Comparer”."
    _B_HINT = "Paste hex here, load a file, or use “Send to Comparer”."
    _DIFF_HINT = "Load both sides, then press Compare."

    def __init__(self, main):
        self.root = main.root
        tab = self.root.comparer_tab

        # ── Inputs: two side-by-side blob editors ────────────────────────────
        inputs = ttk.Frame(tab)
        inputs.pack(fill="x", padx=5, pady=8)
        inputs.columnconfigure(0, weight=1, uniform="blob")
        inputs.columnconfigure(1, weight=1, uniform="blob")

        self._caption_a = tk.StringVar()
        self._caption_b = tk.StringVar()
        self._text_a = self._build_input(inputs, 0, "Blob A", self._caption_a, "a")
        self._text_b = self._build_input(inputs, 1, "Blob B", self._caption_b, "b")

        # ── Compare controls + summary ───────────────────────────────────────
        controls = ttk.Frame(tab)
        controls.pack(fill="x", padx=5, pady=(0, 6))
        ttk.Button(controls, text="Compare", command=self.compare).pack(side="left", padx=5)
        ttk.Button(controls, text="Swap A ↔ B", command=self._swap).pack(side="left", padx=5)
        ttk.Button(controls, text="Clear both", command=self._clear_both).pack(side="left", padx=5)
        self._summary = tk.StringVar(value="")
        ttk.Label(controls, textvariable=self._summary).pack(side="left", padx=12)

        # ── Aligned diff view ────────────────────────────────────────────────
        diff_frame = ttk.LabelFrame(tab, text=" Byte diff (mismatches highlighted) ", padding=6)
        diff_frame.pack(fill="both", expand=True, padx=5, pady=(0, 8))
        self._diff = tk.Text(diff_frame, font=("Courier", 10), wrap="none", state="disabled",
                             background="#fbfbfb", foreground="#000000", borderwidth=0)
        vsb = ttk.Scrollbar(diff_frame, orient="vertical", command=self._diff.yview)
        hsb = ttk.Scrollbar(diff_frame, orient="horizontal", command=self._diff.xview)
        self._diff.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._diff.pack(side="left", fill="both", expand=True)
        self._diff.tag_configure("offset", foreground="#666666")
        self._diff.tag_configure("head", foreground="#333333")
        self._diff.tag_configure("diff", background="#ff8787", foreground="#000000")
        self._diff.tag_configure("pad", foreground="#999999")
        self._set_diff(self._DIFF_HINT)

        # Let other tabs (Traffic / Forge → "Send to Comparer") find this pane.
        self.root.comparer_pane = self

    # ── input editor construction ─────────────────────────────────────────────
    def _build_input(self, parent, column, title, caption_var, side):
        frame = ttk.LabelFrame(parent, text=f" {title} ", padding=6)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 4) if column == 0 else (4, 0))

        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        ttk.Label(bar, textvariable=caption_var, foreground="#666666").pack(side="left")
        ttk.Button(bar, text="Clear", width=6,
                   command=lambda: self._clear_side(side)).pack(side="right")
        ttk.Button(bar, text="Load file…", width=10,
                   command=lambda: self._load_file(side)).pack(side="right", padx=4)

        text = tk.Text(frame, height=7, font=("Courier", 10), wrap="char")
        text.pack(fill="both", expand=True, pady=(4, 0))
        caption_var.set(self._A_HINT if side == "a" else self._B_HINT)
        return text

    # ── reading / writing the input boxes ─────────────────────────────────────
    def _get_text(self, side):
        return (self._text_a if side == "a" else self._text_b).get("1.0", "end")

    def _set_text(self, side, value, caption=""):
        widget = self._text_a if side == "a" else self._text_b
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        caption_var = self._caption_a if side == "a" else self._caption_b
        caption_var.set(caption or self._auto_caption(side, value))

    def _auto_caption(self, side, value):
        """A length caption for freshly-set content, or the hint when empty.

        Falls back to the placeholder hint on un-parseable hex so setting the
        box never raises — Compare reports the parse error instead.
        """
        if not value.strip():
            return self._A_HINT if side == "a" else self._B_HINT
        try:
            return f"{len(parse_hex(value))} bytes"
        except ValueError:
            return self._A_HINT if side == "a" else self._B_HINT

    def _clear_side(self, side):
        self._set_text(side, "")

    def _clear_both(self):
        self._clear_side("a")
        self._clear_side("b")
        self._summary.set("")
        self._set_diff(self._DIFF_HINT)

    def _swap(self):
        a, b = self._get_text("a").strip(), self._get_text("b").strip()
        cap_a, cap_b = self._caption_a.get(), self._caption_b.get()
        self._set_text("a", b, cap_b)
        self._set_text("b", a, cap_a)

    # ── external entry points ─────────────────────────────────────────────────
    def load_transactions(self, txs):
        """Load one or more APDU transactions (Traffic / Forge → Comparer).

        The response bytes (data + status word) are used as the blob. Two or
        more transactions fill A and B directly; a single one fills the next
        empty slot, so two successive "Send to Comparer" actions populate both
        sides for comparison.
        """
        blobs = [(self._tx_caption(tx), self._tx_hex(tx)) for tx in txs]
        if not blobs:
            return
        if len(blobs) >= 2:
            self._set_text("a", blobs[0][1], blobs[0][0])
            self._set_text("b", blobs[1][1], blobs[1][0])
        else:
            target = "a" if not self._get_text("a").strip() else "b"
            self._set_text(target, blobs[0][1], blobs[0][0])
        self.compare()

    @staticmethod
    def _tx_hex(tx):
        return f"{(tx.response_data or '')}{tx.response_sw1:02X}{tx.response_sw2:02X}".upper()

    @staticmethod
    def _tx_caption(tx):
        n = len(tx.response_data or "") // 2 + 2  # response data + 2 SW bytes
        return f"INS {tx.request_ins.upper()} response, {n} bytes"

    # ── file loading ──────────────────────────────────────────────────────────
    def _load_file(self, side):
        path = filedialog.askopenfilename(
            title=f"Load Blob {side.upper()}",
            filetypes=[("Any blob", "*.*"), ("ePassport data", "*.epd"),
                       ("Binary", "*.bin"), ("Hex text", "*.hex *.txt")],
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            messagebox.showerror("Load failed", str(e))
            return

        hex_value, caption = self._interpret_file(raw, path)
        if hex_value is None:
            return  # user cancelled the EF picker
        self._set_text(side, hex_value, caption)

    def _interpret_file(self, raw: bytes, path: str):
        """Turn raw file bytes into (uppercase hex, caption).

        Tries, in order: a ``.epd`` JSON snapshot (offer an EF to pull), a
        plain hex-text dump, and finally the raw bytes themselves.
        """
        name = path.rsplit("/", 1)[-1]

        # 1. ePassport snapshot — let the user pick which EF to compare.
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            data = None
        if isinstance(data, dict):
            blobs = _ef_blobs_from_snapshot(data)
            if blobs:
                ef = self._pick_ef(sorted(blobs))
                if ef is None:
                    return None, ""
                return parse_hex(blobs[ef]).hex().upper(), f"{name} · {ef}"

        # 2. Hex text (a dump of hex digits, possibly across many lines).
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            text = None
        if text is not None and text.strip():
            try:
                value = parse_hex(text)
                return value.hex().upper(), f"{name} · {len(value)} bytes (hex)"
            except ValueError:
                pass  # not hex text — fall through to raw bytes

        # 3. Raw binary.
        return raw.hex().upper(), f"{name} · {len(raw)} bytes (raw)"

    def _pick_ef(self, names):
        """Ask which EF to load from a snapshot. Returns the name or None."""
        if len(names) == 1:
            return names[0]
        choice = simpledialog.askstring(
            "Select EF",
            "Snapshot contains multiple EFs. Enter one to compare:\n\n"
            + ", ".join(names),
            parent=self.root,
        )
        if choice is None:
            return None
        choice = choice.strip().upper()
        for name in names:
            if name.upper() == choice:
                return name
        messagebox.showerror("Unknown EF", f"No EF named {choice!r} in this snapshot.")
        return None

    # ── compare + render ──────────────────────────────────────────────────────
    def compare(self):
        try:
            a = parse_hex(self._get_text("a"))
            b = parse_hex(self._get_text("b"))
        except ValueError as e:
            messagebox.showerror("Invalid hex", str(e))
            return

        s = diff_summary(a, b)
        if s["equal"]:
            verdict = "identical"
        else:
            first = "—" if s["first_diff"] is None else f"0x{s['first_diff']:X}"
            verdict = (f"DIFFER · Hamming {s['hamming']}/{s['compared']}"
                       f" · first diff @ {first}")
        delta = f" · Δlen {s['length_delta']}" if s["length_delta"] else ""
        self._summary.set(f"A={s['len_a']}B  B={s['len_b']}B  →  {verdict}{delta}")
        logging.info(
            "COMPARE  lenA=%d lenB=%d equal=%s hamming=%d first_diff=%s",
            s["len_a"], s["len_b"], s["equal"], s["hamming"], s["first_diff"],
        )
        self._render_diff(a, b)

    def _render_diff(self, a: bytes, b: bytes):
        self._diff.configure(state="normal")
        self._diff.delete("1.0", "end")
        self._diff.insert("end",
                          "Offset    A (hex)                  B (hex)\n", ("head",))
        for off in range(0, max(len(a), len(b), 1), 8):
            self._diff.insert("end", "%08X  " % off, ("offset",))
            self._insert_row(a, b, off)
            self._diff.insert("end", "  ")
            self._insert_row(b, a, off)
            self._diff.insert("end", "\n")
        self._diff.configure(state="disabled")

    def _insert_row(self, primary: bytes, other: bytes, off: int):
        """Render one 8-byte row of ``primary``, tagging bytes that differ from
        ``other`` (or that ``other`` lacks) so mismatches stand out."""
        for i in range(8):
            pos = off + i
            if pos < len(primary):
                differs = pos >= len(other) or primary[pos] != other[pos]
                self._diff.insert("end", "%02X " % primary[pos],
                                  ("diff",) if differs else ())
            else:
                self._diff.insert("end", "-- ", ("pad",))

    def _set_diff(self, message):
        self._diff.configure(state="normal")
        self._diff.delete("1.0", "end")
        self._diff.insert("end", message, ("offset",))
        self._diff.configure(state="disabled")
