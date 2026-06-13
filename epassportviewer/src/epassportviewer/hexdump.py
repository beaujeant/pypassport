"""Shared coloured hex-dump renderer.

Both the Traffic and Forge tabs display APDU bytes as an offset / hex / ASCII
dump where each byte is tinted by the APDU field it belongs to (CLA, INS, …).
Keeping the renderer here means the two tabs stay pixel-for-pixel identical and
there is a single place to change the palette or layout.
"""

import tkinter as tk
from tkinter import ttk


# ── Per-field colours used by both the hex dump and its legend ───────────────
FIELD_COLORS = {
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
LEGEND_ORDER = ("CLA", "INS", "P1", "P2", "LC", "DATA", "LE", "SW1", "SW2")


def build_legend(parent, fields=LEGEND_ORDER):
    """Build a row of coloured field swatches and return the frame.

    The frame is returned un-packed so the caller controls geometry and can
    pack extra widgets into it (e.g. a toggle pinned to the right). Pass
    ``fields`` to restrict the swatches shown — the Forge response dump only
    ever carries DATA / SW1 / SW2, so it omits the request-only fields.
    """
    legend = ttk.Frame(parent)
    ttk.Label(legend, text="Fields:").pack(side="left", padx=(0, 4))
    for field in fields:
        # Force solid black text: the default label foreground is a low
        # contrast grey that is hard to read on these pale swatch colours.
        tk.Label(
            legend, text=field, background=FIELD_COLORS[field],
            foreground="#000000",
            padx=5, pady=1, relief="solid", borderwidth=1,
        ).pack(side="left", padx=2)
    return legend


class HexDumpView:
    """A read-only, field-coloured hex-dump pane backed by a Text widget.

    Call :meth:`render` with a flat list of ``(field, hexstring)`` segments —
    each segment's bytes are tinted with that field's colour. :meth:`clear`
    blanks the pane, optionally showing a placeholder message.
    """

    def __init__(self, parent, height=10):
        self._frame = ttk.Frame(parent)
        # Kept in the normal state (not "disabled") so the text renders in solid
        # black; a disabled Text dims to a hard-to-read grey on some platforms.
        # Editing is blocked via _block_edit instead, while copy/select work.
        self._text = tk.Text(
            self._frame, height=height, font=("Courier", 10), wrap="none",
            background="#fbfbfb", borderwidth=0, foreground="#000000",
        )
        self._text.bind("<Key>", self._block_edit)
        self._text.bind("<<Paste>>", lambda e: "break")
        self._text.bind("<Button-2>", lambda e: "break")
        vsb = ttk.Scrollbar(self._frame, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=vsb.set)
        self._text.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._text.tag_configure("offset", foreground="#666666")
        for field, color in FIELD_COLORS.items():
            self._text.tag_configure(field, background=color)

    # ── geometry passthroughs ────────────────────────────────────────────────
    def pack(self, **kwargs):
        self._frame.pack(**kwargs)
        return self

    def grid(self, **kwargs):
        self._frame.grid(**kwargs)
        return self

    @property
    def frame(self):
        return self._frame

    # ── rendering ────────────────────────────────────────────────────────────
    def render(self, segments):
        """Render ``[(field, hexstring), …]`` as a coloured hex dump."""
        # Flatten every field into a (byte, field) list so each byte keeps its tag.
        flat = []
        for field, hexstr in segments:
            try:
                data = bytes.fromhex(hexstr)
            except ValueError:
                continue
            flat.extend((b, field) for b in data)

        self._text.delete("1.0", "end")
        for off in range(0, len(flat), 16):
            chunk = flat[off:off + 16]
            self._text.insert("end", "%08X  " % off, ("offset",))
            for i in range(16):
                if i == 8:
                    self._text.insert("end", " ")
                if i < len(chunk):
                    b, field = chunk[i]
                    self._text.insert("end", "%02X " % b, (field,))
                else:
                    self._text.insert("end", "   ")
            self._text.insert("end", " |")
            for b, field in chunk:
                ch = chr(b) if 32 <= b < 127 else "."
                self._text.insert("end", ch, (field,))
            self._text.insert("end", "|\n")

    def clear(self, message=""):
        self._text.delete("1.0", "end")
        if message:
            self._text.insert("end", message, ("offset",))

    @staticmethod
    def _block_edit(event):
        # Allow copy/select-all shortcuts and cursor movement; block edits.
        if event.state & 0x4 and event.keysym.lower() in ("c", "a"):
            return None
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End",
                             "Prior", "Next"):
            return None
        return "break"
