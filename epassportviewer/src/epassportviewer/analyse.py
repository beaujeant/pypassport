"""Security attack workbench for a passport.

The View tab owns the routine ICAO 9303 authenticity checks (DG integrity,
SOD signature verification and Active Authentication). This pane keeps the
broader attack workflows.

The panels are a thin GUI over the attack modules in C{pypassport.attacks},
probing the passport for known weaknesses:

  - MAC traceability (Chothia & Smirnov) — recognise a passport from a
    captured message/MAC pair.
  - Active Authentication misuses — run AA before BAC, use the chip as a
    signing oracle, and trace a passport through its RSA modulus.
  - BAC brute force — exhaust the low-entropy MRZ key space, online against a
    live chip or offline against a captured pair.

Everything talks to the card, so each action runs on a background thread to
keep the UI responsive; the C{logging} output is streamed live into the output
box.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from collections.abc import Callable
from tkinter import ttk, filedialog

from pypassport.doc9303.mrz import MRZ
from pypassport.attacks.mac_traceability import MacTraceability
from pypassport.attacks.active_authentication_traceability import AATraceability
from pypassport.attacks.sign_everything import SignEverything
from pypassport.attacks.brute_force import BruteForce

from . import theme


class _TextHandler(logging.Handler):
    """A logging handler that mirrors records into the output Text widget."""

    def __init__(self, pane):
        super().__init__()
        self._pane = pane

    def emit(self, record):
        # write() is thread-safe (it enqueues for the Tk main thread).
        self._pane.write(self.format(record))


class AnalysePane:
    def __init__(self, main, tab: ttk.Frame):
        self.parent = main
        self.root = main.root
        self.tab = tab
        tab = self.tab
        self._busy = False
        # Background attacks marshal UI work back to the Tk main thread through
        # this queue, drained on a periodic timer.
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()

        intro = ttk.Label(
            tab,
            text=(
                "Run security-research attacks against the passport on the reader. "
                "The MRZ-based actions "
                "use the Number / DoB / Expiry (and optional CAN) fields above."
            ),
            wraplength=1060,
            justify="left",
        )
        intro.pack(fill="x", padx=8, pady=(8, 4))

        # Two columns of attack panels, with the output box spanning the bottom.
        body = ttk.Frame(tab)
        body.pack(fill="both", expand=True, padx=4)
        left = ttk.Frame(body)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)

        self._build_mac_traceability(left)
        self._build_brute_force(left)
        self._build_active_authentication(right)

        self._build_output(tab)

        # Stream attack logging into the output box for the pane's lifetime.
        handler = _TextHandler(self)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(handler)

        self.root.after(100, self._drain)

    # ── MAC traceability ──────────────────────────────────────────────────────
    def _build_mac_traceability(self, parent):
        frame = ttk.LabelFrame(parent, text=" MAC traceability ", padding=8)
        frame.pack(fill="x", padx=4, pady=6)

        ttk.Label(
            frame,
            wraplength=500,
            justify="left",
            text="Recognise a passport from a captured message/MAC pair.",
        ).pack(anchor="w", pady=(0, 6))

        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Button(row, text="Check vulnerability", command=self._mac_is_vulnerable).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="Save pair...", command=self._mac_save_pair).pack(side="left", padx=4)
        ttk.Button(row, text="Check from file...", command=self._mac_check_file).pack(side="left", padx=4)

    def _mac_is_vulnerable(self):
        mrz = self._mrz_string()
        if mrz is None:
            return

        def job(iso):
            attack = MacTraceability(iso, mrz)
            vulnerable, comment = attack.is_vulnerable()
            self.write(f"MAC traceability: {'VULNERABLE' if vulnerable else 'not vulnerable'}")
            self.write(f"  {comment}")

        self._run("MAC traceability check", job)

    def _mac_save_pair(self):
        mrz = self._mrz_string()
        if mrz is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save message/MAC pair",
            defaultextension=".pair",
        )
        if not path:
            return

        def job(iso):
            attack = MacTraceability(iso, mrz)
            directory, name = self._split_path(path)
            saved = attack.save_pair(path=directory, filename=name)
            self.write(f"Saved message/MAC pair to {saved}")

        self._run("Save pair", job)

    def _mac_check_file(self):
        path = filedialog.askopenfilename(title="Open a saved message/MAC pair")
        if not path:
            return

        def job(iso):
            attack = MacTraceability(iso)
            belongs = attack.check_from_file(path=path)
            self.write(
                "Passport on the reader " + ("IS" if belongs else "is NOT") + " the one that produced the saved pair."
            )

        self._run("Check from file", job)

    # ── Active Authentication ─────────────────────────────────────────────────
    def _build_active_authentication(self, parent):
        frame = ttk.LabelFrame(parent, text=" Active Authentication ", padding=8)
        frame.pack(fill="x", padx=4, pady=6)

        ttk.Button(frame, text="Check AA before BAC", command=self._aa_before_bac).pack(anchor="w", pady=(0, 6))

        # Sign-everything oracle.
        sign = ttk.Frame(frame)
        sign.pack(fill="x", pady=(0, 6))
        ttk.Label(sign, text="Sign 64-bit challenge (16 hex):").pack(side="left")
        self._sign_msg = tk.StringVar(value="1122334455667788")
        ttk.Entry(sign, textvariable=self._sign_msg, width=20).pack(side="left", padx=4)
        self._sign_verify = tk.BooleanVar(value=False)
        ttk.Checkbutton(sign, text="verify (DG15)", variable=self._sign_verify).pack(side="left", padx=4)
        ttk.Button(sign, text="Sign", command=self._sign).pack(side="left", padx=4)

        # AA traceability (modulus lower-bound).
        trace = ttk.Frame(frame)
        trace.pack(fill="x", pady=(6, 0))
        ttk.Label(trace, text="Rounds:").pack(side="left")
        self._aa_rounds = tk.StringVar(value="100")
        ttk.Entry(trace, textvariable=self._aa_rounds, width=6).pack(side="left", padx=4)
        ttk.Button(trace, text="Highest signature", command=self._aa_highest).pack(side="left", padx=4)
        ttk.Button(trace, text="Modulus (DG15)", command=self._aa_modulus).pack(side="left", padx=4)

        cmp = ttk.Frame(frame)
        cmp.pack(fill="x", pady=(6, 0))
        ttk.Label(cmp, text="Modulus:").grid(row=0, column=0, sticky="w")
        self._aa_modulo_val = tk.StringVar()
        ttk.Entry(cmp, textvariable=self._aa_modulo_val).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(cmp, text="Signature:").grid(row=1, column=0, sticky="w")
        self._aa_sign_val = tk.StringVar()
        ttk.Entry(cmp, textvariable=self._aa_sign_val).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Button(cmp, text="Compare", command=self._aa_compare).grid(row=0, column=2, rowspan=2, padx=4)
        cmp.columnconfigure(1, weight=1)

    def _aa_before_bac(self):
        def job(iso):
            vulnerable = AATraceability(iso).is_vulnerable()
            self.write(
                "Active Authentication before BAC: " + ("POSSIBLE (vulnerable)" if vulnerable else "not possible")
            )

        self._run("AA before BAC", job)

    def _sign(self):
        message = self._sign_msg.get().strip()
        mrz = self._mrz_string() if self._sign_verify.get() else None
        if self._sign_verify.get() and mrz is None:
            return

        def job(iso):
            signature, verified = SignEverything(iso).sign(message, mrz)
            self.write(f"Signature: {signature}")
            if mrz is not None:
                self.write(f"  verified against DG15: {verified}")

        self._run("Sign challenge", job)

    def _aa_highest(self):
        try:
            rounds = int(self._aa_rounds.get())
        except ValueError:
            self.write("Rounds must be an integer.")
            return

        def job(iso):
            highest = AATraceability(iso).get_highest_sign(rounds)
            self.write(f"Highest signature: {highest}")
            self._post(lambda: self._aa_sign_val.set(highest))

        self._run("Highest signature", job)

    def _aa_modulus(self):
        mrz = self._mrz_string()
        if mrz is None:
            return

        def job(iso):
            modulo = AATraceability(iso).get_modulo(mrz)
            self.write(f"Modulus: {modulo}")
            self._post(lambda: self._aa_modulo_val.set(modulo))

        self._run("Read modulus", job)

    def _aa_compare(self):
        modulo = self._aa_modulo_val.get().strip()
        signature = self._aa_sign_val.get().strip()
        if not modulo or not signature:
            self.write("Provide both a modulus and a signature to compare.")
            return
        try:
            same = AATraceability.may_belong_to(modulo, signature)
            gap = AATraceability.compare(modulo, signature)
        except ValueError:
            self.write("Modulus and signature must be hex strings.")
            return
        self.write(f"May belong to the same passport: {same} (gap {gap:.4f}% of the modulus)")

    # ── BAC brute force ───────────────────────────────────────────────────────
    def _build_brute_force(self, parent):
        frame = ttk.LabelFrame(parent, text=" BAC brute force ", padding=8)
        frame.pack(fill="x", padx=4, pady=6)

        ttk.Label(
            frame,
            wraplength=500,
            justify="left",
            text="Exhaust the MRZ key space. Leave a range empty for its default.",
        ).pack(anchor="w", pady=(0, 6))

        grid = ttk.Frame(frame)
        grid.pack(fill="x")
        self._bf = {}
        for r, (label, lo, hi) in enumerate(
            (
                ("Document no.", "id_low", "id_high"),
                ("Date of birth (YYMMDD)", "dob_low", "dob_high"),
                ("Expiry (YYMMDD)", "exp_low", "exp_high"),
            )
        ):
            ttk.Label(grid, text=label).grid(row=r, column=0, sticky="w", pady=2)
            self._bf[lo] = tk.StringVar()
            self._bf[hi] = tk.StringVar()
            ttk.Entry(grid, textvariable=self._bf[lo], width=14).grid(row=r, column=1, padx=4)
            ttk.Label(grid, text="→").grid(row=r, column=2)
            ttk.Entry(grid, textvariable=self._bf[hi], width=14).grid(row=r, column=3, padx=4)

        ttk.Button(frame, text="Brute force online (live card)", command=self._bf_online).pack(anchor="w", pady=(6, 2))

        offline = ttk.Frame(frame)
        offline.pack(fill="x", pady=(4, 0))
        ttk.Label(offline, text="Captured pair (hex):").pack(side="left")
        self._bf_pair = tk.StringVar()
        ttk.Entry(offline, textvariable=self._bf_pair).pack(side="left", fill="x", expand=True, padx=4)

        offbtn = ttk.Frame(frame)
        offbtn.pack(fill="x", pady=(4, 0))
        ttk.Button(offbtn, text="Brute force offline", command=self._bf_offline).pack(side="left", padx=(0, 4))
        ttk.Button(offbtn, text="Forge sample pair from MRZ", command=self._bf_forge_pair).pack(side="left", padx=4)

    def _configure_ranges(self, attack):
        """Apply the range entries to a BruteForce instance. Returns ok, error."""

        def pair(lo, hi):
            return (self._bf[lo].get().strip() or None, self._bf[hi].get().strip() or None)

        attack.set_id(*pair("id_low", "id_high"))
        attack.set_dob(*pair("dob_low", "dob_high"))
        attack.set_exp_date(*pair("exp_low", "exp_high"))
        return attack.check()

    def _bf_online(self):
        def job(iso):
            attack = BruteForce(iso)
            ok, error = self._configure_ranges(attack)
            if not ok:
                self.write("Invalid range:\n" + error)
                return
            found = attack.exploit(reset=True)
            self.write(f"Online brute force result: {found if found else 'not found'}")

        self._run("Online brute force", job)

    def _bf_offline(self):
        pair = self._bf_pair.get().strip().replace(" ", "")
        if not pair:
            self.write("Paste a captured message/MAC pair first.")
            return

        def job(_iso):
            attack = BruteForce()
            ok, error = self._configure_ranges(attack)
            if not ok:
                self.write("Invalid range:\n" + error)
                return
            found = attack.exploit_offline(pair)
            self.write(f"Offline brute force result: {found if found else 'not found'}")

        self._run("Offline brute force", job, needs_card=False)

    def _bf_forge_pair(self):
        mrz = self._mrz_string()
        if mrz is None:
            return
        pair = BruteForce().init_offline(mrz)
        self._bf_pair.set(pair)
        self.write(f"Forged sample pair from MRZ: {pair}")

    # ── Output box ────────────────────────────────────────────────────────────
    def _build_output(self, tab):
        frame = ttk.LabelFrame(tab, text=" Output ", padding=6)
        frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        self._out = tk.Text(frame, height=10, wrap="word", state="disabled")
        theme.style_text(self._out)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self._out.yview)
        self._out.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._out.pack(side="left", fill="both", expand=True)

        ttk.Button(tab, text="Clear output", command=self._clear).pack(anchor="e", padx=8, pady=(0, 6))

    def write(self, text):
        """Append a line to the output box. Safe to call from any thread."""
        self._post(lambda: self._append(text))

    def _append(self, text):
        self._out.configure(state="normal")
        self._out.insert("end", text + "\n")
        self._out.see("end")
        self._out.configure(state="disabled")

    def _post(self, fn):
        """Schedule C{fn} to run on the Tk main thread."""
        self._queue.put(fn)

    def _drain(self):
        try:
            while True:
                fn = self._queue.get_nowait()
                try:
                    fn()
                except Exception:
                    logging.exception("Security attacks: UI update failed")
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _clear(self):
        self._out.configure(state="normal")
        self._out.delete("1.0", "end")
        self._out.configure(state="disabled")

    # ── Shared helpers ────────────────────────────────────────────────────────
    def _mrz_string(self):
        """Build the MRZ string from the top input fields, or None if missing."""
        doc = self.parent.doc_number.get().strip()
        dob = self.parent.dob.get().strip()
        exp = self.parent.expiry.get().strip()
        if not (doc and dob and exp):
            self.write("Enter the MRZ (Number + DoB + Expiry) above first.")
            return None
        return MRZ((doc, dob, exp)).get_mrz()

    @staticmethod
    def _split_path(path):
        import os

        head, tail = os.path.split(path)
        return (head or ".", tail or "pair")

    def _ensure_reader(self):
        """Make sure a reader is connected. Touches Tk — call on the main thread."""
        if not self.parent.reader:
            self.parent.get_reader()
        if not self.parent.reader:
            self.write("No reader connected — start the PCSC service and refresh.")
            return False
        return True

    def _get_card(self):
        """Return the shared ISO7816 channel for an attack, labelled "security".

        Attacks run on the same shared channel as the rest of the app (there is
        only one physical card). Several of them reset the card and tear down
        Secure Messaging by design, so after an attack the next read on the View
        tab re-establishes BAC/PACE — that re-auth is intrinsic to the attack,
        not redundant work.
        """
        if not self._ensure_reader():
            return None
        iso = self.parent.ensure_iso7816()
        iso.source = "security"
        return iso

    def _run(self, label, job, needs_card=True):
        """Run C{job} on a background thread, serialising card access."""
        if self._busy:
            self.write("An analysis is already running — wait for it to finish.")
            return

        iso = self._get_card() if needs_card else None
        if needs_card and iso is None:
            return

        self._busy = True
        self.write(f"▶ {label}...")

        def worker():
            try:
                job(iso)
            except Exception as e:
                self.write(f"✗ {label} failed: {e}")
            finally:
                self._post(self._finish)

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self):
        self._busy = False
