"""Intercept tab — a Burp-style proxy for the card.

Pause, inspect, edit, forward or drop command APDUs in flight. When
interception is *on*, every command APDU is held before it reaches the chip
and shown here in an editable hex/field view; the read thread blocks until the
user clicks **Forward** (send the possibly edited command) or **Drop** (abort
this command without touching the card). When interception is *off*, a small
table of match-&-replace rules rewrites commands automatically.

Threading: the ISO 7816 transport may call our intercept callback from a
worker thread (when the read runs off the Tk main loop) or from the main
thread (the current viewer reads inline). Both are handled:

* Worker thread  -> hand the held request to the UI through a queue and block
  on a ``threading.Event`` (with a timeout) until the user acts. A periodic
  ``root.after`` poller drains the queue on the Tk thread.
* Main thread    -> show the request and pump a nested event loop with
  ``wait_variable`` so the UI stays responsive while the call blocks.

All Tk widget mutation happens on the Tk thread either way.
"""

import logging
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from pypassport.interceptor import Interceptor, Rule
from pypassport.iso7816 import APDUCommand


# How long the transport will block waiting for the user before auto-forwarding
# the command unchanged, so a forgotten/closed window never hangs a read.
_DECISION_TIMEOUT_S = 120.0
_POLL_MS = 100

_FIELD_ORDER = ("cla", "ins", "p1", "p2", "lc", "data", "le")


class _HeldRequest:
    """A command APDU held pending a Forward/Drop decision."""

    def __init__(self, apdu):
        self.original = apdu
        self.result = apdu            # default action is forward-unchanged
        self.event = threading.Event()
        self.decision_var = None      # tk.StringVar, only used on the main thread


class InterceptPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self.tab = self.root.intercept_tab

        self.interceptor = Interceptor()
        self.interceptor.callback = self._intercept_callback

        self._queue = queue.Queue()
        self._held = None             # the request currently shown in the editor
        self._rules = []              # parallel to interceptor.rules, for the listbox

        self._build_ui()
        # Drain held requests posted by worker threads on the Tk main loop.
        self.root.after(_POLL_MS, self._poll_queue)

    # -- UI construction ----------------------------------------------------

    def _build_ui(self):
        # Toggle
        toggle_frame = ttk.LabelFrame(self.tab, text=" Interception ", padding=10)
        toggle_frame.pack(fill="x", pady=8, padx=5)

        self.intercept_on = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toggle_frame,
            text="Intercept is on — hold every APDU for review",
            variable=self.intercept_on,
            command=self._toggle_intercept,
        ).pack(side="left", padx=5)

        self.status_label = ttk.Label(toggle_frame, text="Off — rules apply automatically")
        self.status_label.pack(side="right", padx=5)

        # Held-request editor
        editor = ttk.LabelFrame(self.tab, text=" Held request ", padding=10)
        editor.pack(fill="x", pady=8, padx=5)

        self.fields = {}
        widths = {"cla": 4, "ins": 4, "p1": 4, "p2": 4, "lc": 6, "data": 50, "le": 6}
        labels = {
            "cla": "CLA", "ins": "INS", "p1": "P1", "p2": "P2",
            "lc": "LC", "data": "DATA", "le": "LE",
        }
        row = ttk.Frame(editor)
        row.pack(fill="x", pady=5)
        for f in _FIELD_ORDER:
            ttk.Label(row, text=labels[f] + ":").pack(side="left", padx=(8, 2))
            var = tk.StringVar()
            self.fields[f] = var
            ttk.Entry(row, width=widths[f], textvariable=var).pack(side="left")

        action_row = ttk.Frame(editor)
        action_row.pack(fill="x", pady=5)
        self.forward_button = ttk.Button(
            action_row, text="Forward", command=self._on_forward, state="disabled"
        )
        self.forward_button.pack(side="left", padx=5)
        self.drop_button = ttk.Button(
            action_row, text="Drop", command=self._on_drop, state="disabled"
        )
        self.drop_button.pack(side="left", padx=5)
        self.held_label = ttk.Label(action_row, text="No request held.")
        self.held_label.pack(side="left", padx=10)

        # Match-&-replace rules
        rules_frame = ttk.LabelFrame(
            self.tab, text=" Match & replace rules (applied automatically when off) ", padding=10
        )
        rules_frame.pack(fill="both", expand=True, pady=8, padx=5)

        entry_row = ttk.Frame(rules_frame)
        entry_row.pack(fill="x", pady=5)

        ttk.Label(entry_row, text="Match:").pack(side="left", padx=(0, 4))
        self.rule_match = {}
        for f in ("cla", "ins", "p1", "p2"):
            ttk.Label(entry_row, text=f.upper()).pack(side="left", padx=(6, 1))
            var = tk.StringVar()
            self.rule_match[f] = var
            ttk.Entry(entry_row, width=4, textvariable=var).pack(side="left")

        ttk.Label(entry_row, text="  Replace:").pack(side="left", padx=(10, 4))
        self.rule_replace = {}
        for f in ("p1", "p2", "data"):
            ttk.Label(entry_row, text=f.upper()).pack(side="left", padx=(6, 1))
            width = 30 if f == "data" else 4
            var = tk.StringVar()
            self.rule_replace[f] = var
            ttk.Entry(entry_row, width=width, textvariable=var).pack(side="left")

        ttk.Button(entry_row, text="Add rule", command=self._add_rule).pack(side="left", padx=10)

        list_row = ttk.Frame(rules_frame)
        list_row.pack(fill="both", expand=True, pady=5)
        self.rules_list = tk.Listbox(list_row, height=6)
        self.rules_list.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(list_row, orient="vertical", command=self.rules_list.yview)
        scroll.pack(side="right", fill="y")
        self.rules_list.configure(yscrollcommand=scroll.set)

        ttk.Button(rules_frame, text="Remove selected", command=self._remove_rule).pack(
            side="left", pady=5
        )

    # -- interception toggle ------------------------------------------------

    def _toggle_intercept(self):
        on = self.intercept_on.get()
        self.interceptor.enabled = on
        if on:
            self.status_label.configure(text="On — holding every APDU")
            logging.info("APDU interception enabled")
        else:
            self.status_label.configure(text="Off — rules apply automatically")
            logging.info("APDU interception disabled")
            # Release anything currently held so an in-flight read can finish.
            if self._held is not None:
                self._resolve(self._held.original)

    # -- the transport callback (may run on any thread) ---------------------

    def _intercept_callback(self, apdu):
        """Hold an APDU until the user forwards or drops it.

        Returns the (possibly edited) APDUCommand, or None to drop. Runs on
        whatever thread ISO7816.transmit runs on.
        """
        request = _HeldRequest(apdu)

        if threading.current_thread() is threading.main_thread():
            # Inline read: pump a nested Tk event loop so the UI stays live.
            request.decision_var = tk.StringVar(master=self.root)
            self._held = request
            self._show_request(request)
            # Safety timeout: auto-forward if the user never acts.
            timer = self.root.after(
                int(_DECISION_TIMEOUT_S * 1000),
                lambda: self._resolve(request.original) if self._held is request else None,
            )
            self.root.wait_variable(request.decision_var)
            self.root.after_cancel(timer)
        else:
            # Worker thread: hand to the UI via the queue and block on the event.
            self._queue.put(request)
            if not request.event.wait(_DECISION_TIMEOUT_S):
                logging.warning("Interceptor timed out; forwarding APDU unchanged")
                self._clear_request_async()
                return request.original

        return request.result

    # -- queue draining on the Tk thread ------------------------------------

    def _poll_queue(self):
        try:
            while True:
                request = self._queue.get_nowait()
                self._held = request
                self._show_request(request)
        except queue.Empty:
            pass
        self.root.after(_POLL_MS, self._poll_queue)

    def _clear_request_async(self):
        """Clear the editor from a worker thread (timeout path)."""
        self.root.after(0, self._clear_editor)

    # -- editor display -----------------------------------------------------

    def _show_request(self, request):
        apdu = request.original
        for f in _FIELD_ORDER:
            self.fields[f].set(getattr(apdu, f))
        self.held_label.configure(text=f"Holding: {repr(apdu)}")
        self.forward_button.configure(state="normal")
        self.drop_button.configure(state="normal")

    def _clear_editor(self):
        for f in _FIELD_ORDER:
            self.fields[f].set("")
        self.held_label.configure(text="No request held.")
        self.forward_button.configure(state="disabled")
        self.drop_button.configure(state="disabled")

    # -- Forward / Drop -----------------------------------------------------

    def _on_forward(self):
        if self._held is None:
            return
        try:
            edited = APDUCommand(
                self.fields["cla"].get(),
                self.fields["ins"].get(),
                self.fields["p1"].get(),
                self.fields["p2"].get(),
                # Fields are forwarded verbatim, including Lc. Clear the Lc box
                # to have it derived from DATA; leaving a mismatched value is
                # intentional (testing Lc/data inconsistencies is a feature).
                self.fields["lc"].get(),
                self.fields["data"].get(),
                self.fields["le"].get(),
            )
        except Exception as e:
            messagebox.showerror("Invalid APDU", f"Could not parse the edited APDU: {e}")
            return
        self._resolve(edited)

    def _on_drop(self):
        if self._held is None:
            return
        self._resolve(None)

    def _resolve(self, result):
        """Deliver the decision to the blocked transport thread and clear the UI."""
        request = self._held
        if request is None:
            return
        request.result = result
        self._held = None
        request.event.set()
        if request.decision_var is not None:
            request.decision_var.set("done")  # unblocks wait_variable on the main thread
        self._clear_editor()

    # -- rules --------------------------------------------------------------

    def _add_rule(self):
        match = {f: v.get().strip() for f, v in self.rule_match.items() if v.get().strip()}
        replace = {f: v.get().strip() for f, v in self.rule_replace.items() if v.get().strip()}
        if not match:
            messagebox.showerror("Invalid rule", "A rule needs at least one match field.")
            return
        if not replace:
            messagebox.showerror("Invalid rule", "A rule needs at least one replace field.")
            return
        rule = Rule(match=match, replace=replace)
        self.interceptor.add_rule(rule)
        self._rules.append(rule)
        self.rules_list.insert(
            "end",
            f"match {match}  ->  replace {replace}",
        )
        for v in self.rule_match.values():
            v.set("")
        for v in self.rule_replace.values():
            v.set("")
        logging.info(f"Added intercept rule: {rule!r}")

    def _remove_rule(self):
        selection = self.rules_list.curselection()
        if not selection:
            return
        index = selection[0]
        rule = self._rules.pop(index)
        try:
            self.interceptor.rules.remove(rule)
        except ValueError:
            pass
        self.rules_list.delete(index)
        logging.info(f"Removed intercept rule: {rule!r}")
