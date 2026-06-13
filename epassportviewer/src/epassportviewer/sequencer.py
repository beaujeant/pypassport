"""Sequencer tab — collect and analyse GET CHALLENGE nonces.

This is the proper replacement for the old Custom pane's ``dump_randomness`` /
``download_data`` helpers (both buggy duplicates). It resets the card
connection, issues GET CHALLENGE N times, and reports basic randomness stats:
a byte-frequency histogram, Shannon entropy per byte position, and the number
of duplicate nonces. The collected nonces can be saved to disk.
"""

import logging
import math
from collections import Counter

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:  # headless (e.g. CI): the pure helpers below stay importable
    tk = ttk = filedialog = messagebox = None

from pypassport.iso7816 import ISO7816
from pypassport.utils import toHexString


_DEFAULT_N = 200
_MAX_N = 100000


# ── Pure helpers (no Tk, no card) ─────────────────────────────────────────────
def shannon_entropy(values) -> float:
    """Shannon entropy of a sequence of symbols, in bits."""
    values = list(values)
    if not values:
        return 0.0
    total = len(values)
    return -sum(
        (c / total) * math.log2(c / total) for c in Counter(values).values()
    )


def randomness_stats(challenges) -> dict:
    """Compute randomness statistics over a list of nonce ``bytes``.

    Returns a dict with:

    * ``total`` / ``unique`` / ``duplicates`` — nonce counts;
    * ``nonce_len`` — the shortest nonce length (positions beyond it are
      ignored so a stray short response can't crash the per-position analysis);
    * ``byte_histogram`` — a 256-entry list counting every byte value seen;
    * ``position_entropy`` — Shannon entropy (bits) of each byte position;
    * ``overall_entropy`` — entropy over all bytes pooled together.
    """
    total = len(challenges)
    unique = len(set(challenges))
    nonce_len = min((len(c) for c in challenges), default=0)

    histogram = [0] * 256
    for nonce in challenges:
        for byte in nonce:
            histogram[byte] += 1

    position_entropy = [
        shannon_entropy(nonce[pos] for nonce in challenges)
        for pos in range(nonce_len)
    ]
    overall_entropy = shannon_entropy(
        byte for nonce in challenges for byte in nonce[:nonce_len]
    )

    return {
        "total": total,
        "unique": unique,
        "duplicates": total - unique,
        "nonce_len": nonce_len,
        "byte_histogram": histogram,
        "position_entropy": position_entropy,
        "overall_entropy": overall_entropy,
    }


def format_report(stats: dict) -> str:
    """Render :func:`randomness_stats` output as a human-readable report."""
    lines = [
        f"Nonces collected : {stats['total']}",
        f"Unique nonces    : {stats['unique']}",
        f"Duplicate nonces : {stats['duplicates']}",
        f"Nonce length     : {stats['nonce_len']} byte(s)",
        f"Overall entropy  : {stats['overall_entropy']:.4f} bits/byte (max 8.0)",
        "",
        "Shannon entropy per byte position:",
    ]
    for pos, h in enumerate(stats["position_entropy"]):
        bar = "#" * int(round(h / 8 * 40))
        lines.append(f"  byte[{pos}]  {h:6.4f} bits  |{bar:<40}|")

    lines += ["", "Byte-value frequency histogram (16-value bins):"]
    histogram = stats["byte_histogram"]
    bin_counts = [sum(histogram[b:b + 16]) for b in range(0, 256, 16)]
    peak = max(bin_counts) if bin_counts else 0
    for i, count in enumerate(bin_counts):
        lo, hi = i * 16, i * 16 + 15
        bar = "#" * (int(round(count / peak * 40)) if peak else 0)
        lines.append(f"  {lo:02X}-{hi:02X}  {count:6d}  |{bar:<40}|")
    return "\n".join(lines)


class SequencerPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        tab = self.root.sequencer_tab

        self._challenges = []  # list[bytes], the most recent run

        # ── Controls ─────────────────────────────────────────────────────────
        controls = ttk.LabelFrame(tab, text=" GET CHALLENGE sequence ", padding=10)
        controls.pack(fill="x", padx=5, pady=8)

        ttk.Label(controls, text="Number of challenges (N):").pack(side="left", padx=(4, 4))
        self._n_var = tk.StringVar(value=str(_DEFAULT_N))
        ttk.Entry(controls, textvariable=self._n_var, width=8).pack(side="left")

        self._run_btn = ttk.Button(controls, text="Run", command=self._run)
        self._run_btn.pack(side="left", padx=8)
        self._save_btn = ttk.Button(controls, text="Save nonces…", command=self._save, state="disabled")
        self._save_btn.pack(side="left")

        self._status = tk.StringVar(value="")
        ttk.Label(controls, textvariable=self._status, foreground="#666666").pack(side="left", padx=12)

        # ── Report ───────────────────────────────────────────────────────────
        report_frame = ttk.LabelFrame(tab, text=" Randomness report ", padding=6)
        report_frame.pack(fill="both", expand=True, padx=5, pady=(0, 8))
        self._report = tk.Text(report_frame, font=("Courier", 10), wrap="none",
                               state="disabled", background="#fbfbfb",
                               foreground="#000000", borderwidth=0)
        vsb = ttk.Scrollbar(report_frame, orient="vertical", command=self._report.yview)
        self._report.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._report.pack(side="left", fill="both", expand=True)
        self._set_report("Set N and press Run to collect GET CHALLENGE nonces.")

        self.root.sequencer_pane = self

    # ── readiness (mirrors Forge) ─────────────────────────────────────────────
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

    # ── run ────────────────────────────────────────────────────────────────────
    def _parse_n(self):
        raw = self._n_var.get().strip()
        try:
            n = int(raw)
        except ValueError:
            raise ValueError(f"{raw!r} is not a whole number.")
        if n < 1:
            raise ValueError("N must be at least 1.")
        if n > _MAX_N:
            raise ValueError(f"N must be at most {_MAX_N}.")
        return n

    def _run(self):
        try:
            n = self._parse_n()
        except ValueError as e:
            messagebox.showerror("Invalid N", str(e))
            return
        if not self._get_ready():
            return

        iso = self.parent.iso7816
        challenges = []
        self._run_btn.configure(state="disabled")
        self._save_btn.configure(state="disabled")
        try:
            # Reset to a clean connection (drops any SM channel) and select the
            # eMRTD application, exactly as the BAC handshake would before
            # issuing GET CHALLENGE.
            iso.rstConnection()
            for i in range(n):
                challenges.append(bytes(iso.getChallenge()))
                if i % 10 == 0 or i == n - 1:
                    self._status.set(f"Collecting… {i + 1}/{n}")
                    self.root.update_idletasks()
        except Exception as e:
            logging.exception("Sequencer: GET CHALLENGE failed")
            messagebox.showerror(
                "Sequence failed",
                f"Collected {len(challenges)} nonce(s) before the error:\n\n{e}",
            )
        finally:
            self._run_btn.configure(state="normal")

        self._challenges = challenges
        if not challenges:
            self._status.set("No nonces collected.")
            self._set_report("No nonces collected.")
            return

        stats = randomness_stats(challenges)
        self._set_report(format_report(stats))
        self._save_btn.configure(state="normal")
        self._status.set(f"Done — {stats['total']} nonces, {stats['duplicates']} duplicate(s).")
        logging.info(
            "SEQUENCER  collected=%d unique=%d duplicates=%d overall_entropy=%.4f",
            stats["total"], stats["unique"], stats["duplicates"], stats["overall_entropy"],
        )

    # ── session scratch (save / restore) ──────────────────────────────────────
    def get_scratch(self):
        """Capture the collected nonces and N for a saved session.

        Returns None when nothing has been collected so an unused Sequencer
        adds nothing to the session file.
        """
        if not self._challenges:
            return None
        return {
            "n": self._n_var.get(),
            "challenges": [c.hex().upper() for c in self._challenges],
        }

    def load_scratch(self, state):
        """Restore collected nonces from saved-session scratch and re-report."""
        if not isinstance(state, dict):
            return
        if state.get("n"):
            self._n_var.set(str(state["n"]))
        challenges = []
        for hex_str in state.get("challenges", []):
            try:
                challenges.append(bytes.fromhex(hex_str))
            except (ValueError, TypeError):
                continue
        self._challenges = challenges
        if not challenges:
            return
        stats = randomness_stats(challenges)
        self._set_report(format_report(stats))
        self._save_btn.configure(state="normal")
        self._status.set(
            f"Restored — {stats['total']} nonces, {stats['duplicates']} duplicate(s)."
        )

    # ── save ────────────────────────────────────────────────────────────────────
    def _save(self):
        if not self._challenges:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")],
            title="Save collected nonces",
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write("\n".join(toHexString(c) for c in self._challenges) + "\n")
        except OSError as e:
            messagebox.showerror("Save failed", str(e))
            return
        messagebox.showinfo(
            "Nonces saved", f"{len(self._challenges)} nonce(s) saved to {path}."
        )

    # ── report widget ────────────────────────────────────────────────────────
    def _set_report(self, text):
        self._report.configure(state="normal")
        self._report.delete("1.0", "end")
        self._report.insert("end", text)
        self._report.configure(state="disabled")
