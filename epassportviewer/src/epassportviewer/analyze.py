"""Analyze tab — runs the pypassport fingerprint engine against a live card.

The heavy work (a full :class:`~pypassport.fingerprint.Fingerprint` run, or one
of the individual security checks) happens on a worker thread so the Tk event
loop stays responsive. Workers never touch widgets directly: they push progress
and results onto a :class:`queue.Queue`, and a ``root.after`` poller running on
the main thread drains the queue and updates the UI.

Every message is a ``(None, tag, payload)`` triple, matching the shape the
Fingerprint engine already emits (``'slfp'`` for a step label, ``'fp'`` for a
percentage). The pane adds a few tags of its own: ``'log'`` (append a progress
line), ``'report'`` (render a finished Fingerprint result), ``'result'``
(render an individual check's verdict), ``'error'`` (a failed run) and
``'done'`` (re-enable the controls).
"""

import logging
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from pypassport.epassport import EPassport, EPassportException
from pypassport.iso7816 import ISO7816
from pypassport.doc9303.mrz import MRZ
from pypassport.fingerprint import Fingerprint
from pypassport.attacks.mac_traceability import MacTraceability
from pypassport.attacks.active_authentication_traceability import AATraceability
from pypassport.attacks.error_fingerprinting import ErrorFingerprinting


_INTRO = (
    "Run the full fingerprint or an individual check against the card on the "
    "selected reader. A full analysis needs the MRZ (Number / Date of Birth / "
    "Expiry) at the top of the window; it drives BAC and is destructive to any "
    "secure-messaging channel already open in the other tabs."
)


class AnalyzePane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root

        self._queue = queue.Queue()
        self._running = False
        self._poll_id = None
        self._indeterminate = False
        self._buttons = []

        frame = self.root.analyze_tab

        ttk.Label(frame, text=_INTRO, wraplength=1050, justify="left").pack(
            fill="x", padx=10, pady=(10, 4)
        )

        # ── Controls ──────────────────────────────────────────────────────────
        controls = ttk.Frame(frame)
        controls.pack(fill="x", padx=10, pady=4)

        self._full_btn = ttk.Button(
            controls, text="Run full analysis", command=self._run_full_analysis
        )
        self._full_btn.pack(side="left", padx=(0, 12))
        self._buttons.append(self._full_btn)

        checks = ttk.LabelFrame(frame, text=" Individual checks ", padding=8)
        checks.pack(fill="x", padx=10, pady=4)
        for label, cmd in (
            ("MAC traceability", self._run_mac_traceability),
            ("AA before BAC", self._run_aa_before_bac),
            ("Error fingerprint", self._run_error_fingerprint),
        ):
            btn = ttk.Button(checks, text=label, command=cmd)
            btn.pack(side="left", padx=4)
            self._buttons.append(btn)

        # ── Progress ──────────────────────────────────────────────────────────
        progress_frame = ttk.LabelFrame(frame, text=" Progress ", padding=8)
        progress_frame.pack(fill="x", padx=10, pady=4)

        self._progress = ttk.Progressbar(progress_frame, mode="determinate", maximum=100)
        self._progress.pack(fill="x", pady=(0, 4))

        self._status_var = tk.StringVar(value="Idle.")
        ttk.Label(progress_frame, textvariable=self._status_var, foreground="#555555").pack(
            anchor="w"
        )

        self._progress_log = scrolledtext.ScrolledText(
            progress_frame, wrap="word", state="disabled", height=6, font=("Courier", 9)
        )
        self._progress_log.pack(fill="x", pady=(4, 0))

        # ── Report ────────────────────────────────────────────────────────────
        report_frame = ttk.LabelFrame(frame, text=" Report ", padding=8)
        report_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        self._report = scrolledtext.ScrolledText(
            report_frame, wrap="word", state="disabled", font=("Courier", 9)
        )
        self._report.pack(fill="both", expand=True)

        self.root.analyze_pane = self

    # ── Readiness guards (mirrors ForgePane._get_ready) ───────────────────────
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

    def _mrz_fields(self):
        """Return a validated (number, dob, expiry) tuple, or None on error."""
        num = self.parent.doc_number.get().strip()
        dob = self.parent.dob.get().strip()
        exp = self.parent.expiry.get().strip()
        if not (num and dob and exp):
            messagebox.showerror(
                "MRZ required",
                "Enter the Number, Date of Birth and Expiry (MRZ) at the top of "
                "the window before running this check.",
            )
            return None
        if not MRZ((num, dob, exp)).checkMRZ():
            messagebox.showerror(
                "Invalid MRZ",
                "The Number / Date of Birth / Expiry do not form a valid MRZ.",
            )
            return None
        return (num, dob, exp)

    # ── Run dispatchers ───────────────────────────────────────────────────────
    def _run_full_analysis(self):
        if not self._claim_run():
            return
        if not self._get_ready():
            self._abort_claim()
            return
        mrz = self._mrz_fields()
        if mrz is None:
            self._abort_claim()
            return
        try:
            # Build a dedicated session: the fingerprint drives its own BAC and
            # connection resets, so it gets its own ISO7816. Publish it as the
            # shared channel so the other tabs reflect the card's new state.
            ep = EPassport(self.parent.reader, mrz, select_aid=False)
            self.parent.iso7816 = ep.iso7816
            fp = Fingerprint(ep, certdir=None, callback=self._queue)
        except EPassportException as e:
            self._abort_claim()
            messagebox.showerror("Analyze failed", str(e))
            return
        except Exception as e:
            logging.exception("Could not start fingerprint analysis")
            self._abort_claim()
            messagebox.showerror("Analyze failed", f"Could not connect to the passport: {e}")
            return
        self._begin_run("Full analysis", determinate=True)
        threading.Thread(target=self._full_worker, args=(fp,), daemon=True).start()

    def _run_mac_traceability(self):
        if not self._claim_run():
            return
        if not self._get_ready():
            self._abort_claim()
            return
        mrz = self._mrz_fields()
        if mrz is None:
            self._abort_claim()
            return
        iso = self.parent.iso7816
        self._begin_run("MAC traceability", determinate=False)
        threading.Thread(target=self._mac_worker, args=(iso, mrz), daemon=True).start()

    def _run_aa_before_bac(self):
        if not self._claim_run():
            return
        if not self._get_ready():
            self._abort_claim()
            return
        iso = self.parent.iso7816
        self._begin_run("AA before BAC", determinate=False)
        threading.Thread(target=self._aa_worker, args=(iso,), daemon=True).start()

    def _run_error_fingerprint(self):
        if not self._claim_run():
            return
        if not self._get_ready():
            self._abort_claim()
            return
        iso = self.parent.iso7816
        self._begin_run("Error fingerprint", determinate=False)
        threading.Thread(target=self._error_worker, args=(iso,), daemon=True).start()

    # ── Workers (run off the main thread; only touch the queue) ────────────────
    def _full_worker(self, fp):
        try:
            res = fp.analyse()
            self._queue.put((None, "report", res))
        except Exception as e:
            logging.exception("Fingerprint analysis failed")
            self._queue.put((None, "error", f"Analysis failed: {e}"))
        finally:
            self._queue.put((None, "done", None))

    def _mac_worker(self, iso, mrz_fields):
        try:
            self._queue.put((None, "slfp", "MAC traceability: establishing legitimate BAC…"))
            attack = MacTraceability(iso, MRZ(mrz_fields))
            self._queue.put((None, "log", "Capturing a message/MAC pair and comparing responses…"))
            vulnerable, comment = attack.isVulnerable()
            verdict = "VULNERABLE" if vulnerable else "Not vulnerable"
            self._queue.put((None, "result", ("MAC traceability", f"{verdict}\n\n{comment}")))
        except Exception as e:
            logging.exception("MAC traceability check failed")
            self._queue.put((None, "error", f"MAC traceability could not run: {e}"))
        finally:
            self._queue.put((None, "done", None))

    def _aa_worker(self, iso):
        try:
            self._queue.put((None, "slfp", "Checking Active Authentication before BAC…"))
            attack = AATraceability(iso)
            vulnerable = attack.isVulnerable()
            if vulnerable:
                text = (
                    "VULNERABLE\n\nThe chip answers INTERNAL AUTHENTICATE before "
                    "BAC, so it signs a challenge without access control — usable "
                    "for Active-Authentication traceability."
                )
            else:
                text = (
                    "Not vulnerable\n\nThe chip refused INTERNAL AUTHENTICATE "
                    "before BAC."
                )
            self._queue.put((None, "result", ("Active Authentication before BAC", text)))
        except Exception as e:
            logging.exception("AA-before-BAC check failed")
            self._queue.put((None, "error", f"AA-before-BAC could not run: {e}"))
        finally:
            self._queue.put((None, "done", None))

    def _error_worker(self, iso):
        try:
            self._queue.put((None, "slfp", "Error fingerprint: probing instructions…"))
            ef = ErrorFingerprinting(iso)
            instructions = ["44", "82", "84", "88", "A4", "B0", "B1"]
            lines = []
            for ins in instructions:
                self._queue.put((None, "log", f"Probing INS {ins}…"))
                ok, ans = ef.sendCustom("00", ins, "00", "00", "", "", "00")
                if ok:
                    lines.append(f"INS {ins}: accepted (resp {ans})")
                else:
                    lines.append(
                        f"INS {ins}: SW1={self._fmt_sw(ans.sw1)} SW2={self._fmt_sw(ans.sw2)}"
                    )
            self._queue.put((None, "result", ("Error fingerprint", "\n".join(lines))))
        except Exception as e:
            logging.exception("Error fingerprint check failed")
            self._queue.put((None, "error", f"Error fingerprint could not run: {e}"))
        finally:
            self._queue.put((None, "done", None))

    # ── Run lifecycle / button state ───────────────────────────────────────────
    def _claim_run(self):
        """Reserve the pane for a single run; False if one is already going."""
        if self._running:
            messagebox.showinfo(
                "Busy", "An analysis is already running. Wait for it to finish."
            )
            return False
        self._running = True
        return True

    def _abort_claim(self):
        """Release a reservation that never started a worker (guard failed)."""
        self._running = False

    def _begin_run(self, title, determinate):
        self._indeterminate = not determinate
        for btn in self._buttons:
            btn.configure(state="disabled")
        self._clear_log()
        self._clear_report()
        self._status_var.set(f"Running: {title}…")
        if determinate:
            self._progress.configure(mode="determinate")
            self._progress["value"] = 0
        else:
            self._progress.configure(mode="indeterminate")
            self._progress.start(12)
        self._schedule_poll()

    def _finish_run(self):
        self._running = False
        if self._indeterminate:
            self._progress.stop()
            self._progress.configure(mode="determinate")
        self._progress["value"] = 100
        for btn in self._buttons:
            btn.configure(state="normal")
        if not self._status_var.get().startswith("Error"):
            self._status_var.set("Done.")

    # ── Queue polling (main thread) ────────────────────────────────────────────
    def _schedule_poll(self):
        self._poll_id = self.root.after(100, self._poll)

    def _poll(self):
        try:
            while True:
                self._handle(self._queue.get_nowait())
        except queue.Empty:
            pass
        if self._running:
            self._schedule_poll()

    def _handle(self, item):
        try:
            _, tag, payload = item
        except (ValueError, TypeError):
            logging.warning("Analyze: ignoring malformed queue item %r", item)
            return

        if tag == "slfp":
            self._status_var.set(str(payload))
            self._append_log(str(payload))
        elif tag == "fp":
            try:
                self._progress["value"] = int(payload)
            except (TypeError, ValueError):
                pass
        elif tag == "log":
            self._append_log(str(payload))
        elif tag == "report":
            self._render_text(self._format_report(payload))
            self._append_log("Report ready.")
        elif tag == "result":
            title, text = payload
            self._render_text(f"{title}\n\n{text}")
            self._append_log(f"{title}: done.")
        elif tag == "error":
            self._status_var.set(f"Error: {payload}")
            self._append_log(f"ERROR: {payload}")
            self._render_text(str(payload))
        elif tag == "done":
            self._finish_run()
        else:
            logging.debug("Analyze: unknown queue tag %r", tag)

    # ── Report formatting ──────────────────────────────────────────────────────
    def _format_report(self, res):
        lines = []

        def section(title):
            lines.append("")
            lines.append(f"=== {title} ===")

        section("Summary")
        gen = res.get("generation", 0)
        lines.append(f"Passport generation     : {gen if gen else 'undetermined'}")
        lines.append(f"BAC                     : {res.get('bac')}")
        lines.append(f"Active Authentication   : {res.get('activeAuth')}")
        lines.append(f"AA before BAC           : {self._yesno(res.get('activeAuthWithoutBac'))}")
        lines.append(f"MAC traceability        : {self._mac_verdict(res.get('macTraceability'))}")
        lines.append(f"Blocks after failed BAC : {self._yesno(res.get('blockAfterFail'))}")
        lines.append(f"Anti-bruteforce delay   : {self._yesno(res.get('delaySecurity'))}")

        section("Chip identifiers")
        lines.append(f"ATR : {res.get('ATR')}")
        lines.append(f"UID : {res.get('UID')}")

        section("Passive Authentication")
        lines.append(f"Verify SOD     : {res.get('verifySOD')}")
        lines.append(f"Hash algorithm : {res.get('Algo')}")
        integrity = res.get("Integrity")
        if isinstance(integrity, dict) and integrity:
            for dg, ok in sorted(integrity.items()):
                lines.append(f"  {dg}: {self._integrity(ok)}")
        else:
            lines.append("  (no integrity result)")

        section("Active Authentication")
        lines.append(f"AA result  : {res.get('activeAuth')}")
        lines.append(f"Public key : {self._short(res.get('pubKey'))}")

        section("Document Signer Certificate")
        lines.append(str(res.get("certSerialNumber") or "N/A"))
        lines.append(str(res.get("certFingerprint") or "N/A"))

        section("Data Groups (size in bytes)")
        dgs = res.get("DGs")
        if isinstance(dgs, list) and dgs:
            for name, size in dgs:
                lines.append(f"  {name}: {size}")
        else:
            lines.append(f"  {dgs}")
        failed = res.get("failedToRead") or []
        if failed:
            lines.append(f"  Failed to read: {', '.join(failed)}")
        rt = res.get("ReadingTime")
        if isinstance(rt, (int, float)):
            lines.append(f"  Reading time: {rt:.2f}s")

        section("Data Group hashes")
        hashes = res.get("Hashes")
        if isinstance(hashes, dict) and hashes:
            for dg, digest in sorted(hashes.items()):
                lines.append(f"  {dg}: {self._hex(digest)}")
        else:
            lines.append("  (no hashes)")

        section("Error fingerprints")
        errors = res.get("Errors")
        if isinstance(errors, dict) and errors:
            for ins, sw in sorted(errors.items()):
                lines.append(f"  INS {ins}: {sw}")
        else:
            lines.append("  (none)")

        section("Probe responses")
        lines.append(f"SELECT (null AID)     : {res.get('selectNull')}")
        lines.append(f"GET CHALLENGE (Le=01) : {res.get('getChallengeNull')}")

        return "\n".join(lines).lstrip("\n")

    @staticmethod
    def _yesno(value):
        if value is True:
            return "Yes"
        if value is False:
            return "No"
        return str(value)

    @staticmethod
    def _integrity(ok):
        if ok is True:
            return "MATCH"
        if ok is False:
            return "MISMATCH"
        return "N/A"

    @staticmethod
    def _mac_verdict(value):
        if isinstance(value, tuple) and len(value) == 2:
            vulnerable, comment = value
            label = "VULNERABLE" if vulnerable else "Not vulnerable"
            return f"{label} ({comment})"
        return str(value)

    @staticmethod
    def _fmt_sw(value):
        return f"{value:#04x}" if isinstance(value, int) else str(value)

    @staticmethod
    def _hex(value):
        if isinstance(value, (bytes, bytearray)):
            return value.hex().upper()
        return str(value)

    @staticmethod
    def _short(value, limit=80):
        text = str(value)
        return text if len(text) <= limit else text[:limit] + "…"

    # ── Text widgets ───────────────────────────────────────────────────────────
    def _append_log(self, text):
        self._progress_log.configure(state="normal")
        self._progress_log.insert("end", text + "\n")
        self._progress_log.see("end")
        self._progress_log.configure(state="disabled")

    def _clear_log(self):
        self._progress_log.configure(state="normal")
        self._progress_log.delete("1.0", "end")
        self._progress_log.configure(state="disabled")

    def _render_text(self, text):
        self._report.configure(state="normal")
        self._report.delete("1.0", "end")
        self._report.insert("end", text)
        self._report.configure(state="disabled")

    def _clear_report(self):
        self._render_text("")
