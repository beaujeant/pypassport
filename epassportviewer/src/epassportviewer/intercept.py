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

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from pypassport.interceptor import Interceptor, Rule
from pypassport.iso7816 import APDUCommand

from . import theme
from .apdu_format import assemble_apdu, describe_apdu_fields

# How long the transport will block waiting for the user before auto-forwarding
# the command unchanged, so a forgotten/closed window never hangs a read.
_DECISION_TIMEOUT_S = 120.0
_POLL_MS = 100

_FIELD_ORDER = ("cla", "ins", "p1", "p2", "lc", "data", "le")


class _HeldRequest:
    """A command APDU held pending a Forward/Drop decision."""

    def __init__(self, apdu):
        self.original = apdu
        self.result = apdu  # default action is forward-unchanged
        self.event = threading.Event()
        self.decision_var = None  # tk.StringVar, only used on the main thread


class InterceptPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self.tab = self.root.intercept_tab

        self.interceptor = Interceptor()
        self.interceptor.callback = self._intercept_callback

        self._queue: queue.Queue[_HeldRequest] = queue.Queue()
        self._held: _HeldRequest | None = None  # the request currently shown in the editor
        self._rules = []  # parallel to interceptor.rules, for the listbox

        self._build_ui()
        # Drain held requests posted by worker threads on the Tk main loop.
        self.root.after(_POLL_MS, self._poll_queue)

    # -- UI construction ----------------------------------------------------

    def _build_ui(self):
        # Toggle
        toggle_frame = ttk.LabelFrame(self.tab, text=" Interception ", padding=10)
        toggle_frame.pack(fill="x", pady=8, padx=5)

        toggle_head = ttk.Frame(toggle_frame)
        toggle_head.pack(fill="x")
        self.intercept_on = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toggle_head,
            text="Intercept is on — hold every APDU for review",
            variable=self.intercept_on,
            command=self._toggle_intercept,
        ).pack(side="left", padx=5)

        self.status_label = ttk.Label(toggle_head, text="Off — rules apply automatically")
        self.status_label.pack(side="right", padx=5)

        breakpoint_row = ttk.Frame(toggle_frame)
        breakpoint_row.pack(fill="x", pady=(8, 0))
        self.breakpoint_on = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            breakpoint_row,
            text="Only hold matching breakpoint",
            variable=self.breakpoint_on,
            command=self._sync_breakpoint,
        ).pack(side="left", padx=(5, 10))
        self.breakpoint_fields = {}
        for field in ("cla", "ins", "p1", "p2", "data"):
            ttk.Label(breakpoint_row, text=field.upper()).pack(side="left", padx=(6, 1))
            var = tk.StringVar()
            var.trace_add("write", lambda *_args: self._sync_breakpoint())
            self.breakpoint_fields[field] = var
            ttk.Entry(breakpoint_row, width=18 if field == "data" else 4, textvariable=var).pack(side="left")

        # Held-request editor
        editor = ttk.LabelFrame(self.tab, text=" Held request ", padding=10)
        editor.pack(fill="x", pady=8, padx=5)

        self.fields = {}
        widths = {"cla": 4, "ins": 4, "p1": 4, "p2": 4, "lc": 6, "data": 50, "le": 6}
        labels = {
            "cla": "CLA",
            "ins": "INS",
            "p1": "P1",
            "p2": "P2",
            "lc": "LC",
            "data": "DATA",
            "le": "LE",
        }
        row = ttk.Frame(editor)
        row.pack(fill="x", pady=5)
        for f in _FIELD_ORDER:
            ttk.Label(row, text=labels[f] + ":").pack(side="left", padx=(8, 2))
            var = tk.StringVar()
            self.fields[f] = var
            ttk.Entry(row, width=widths[f], textvariable=var).pack(side="left")

        raw_row = ttk.Frame(editor)
        raw_row.pack(fill="x", pady=(0, 5))
        ttk.Label(raw_row, text="Raw:").pack(side="left", padx=(8, 2))
        self.held_raw = tk.StringVar()
        ttk.Entry(raw_row, textvariable=self.held_raw, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ttk.Button(raw_row, text="Copy", command=self._copy_held).pack(side="right", padx=4)

        action_row = ttk.Frame(editor)
        action_row.pack(fill="x", pady=5)
        self.forward_button = ttk.Button(action_row, text="Forward edited", command=self._on_forward, state="disabled")
        self.forward_button.pack(side="left", padx=5)
        self.forward_original_button = ttk.Button(
            action_row,
            text="Forward original",
            command=self._on_forward_original,
            state="disabled",
        )
        self.forward_original_button.pack(side="left", padx=5)
        self.drop_button = ttk.Button(action_row, text="Drop", command=self._on_drop, state="disabled")
        self.drop_button.pack(side="left", padx=5)
        self.forge_button = ttk.Button(
            action_row,
            text="Send to Forge",
            command=self._send_held_to_forge,
            state="disabled",
        )
        self.forge_button.pack(side="left", padx=5)
        self.held_label = ttk.Label(action_row, text="No request held.")
        self.held_label.pack(side="left", padx=10)

        # Match-&-replace rules
        rules_frame = ttk.LabelFrame(
            self.tab, text=" Match & replace rules (applied automatically when off) ", padding=10
        )
        rules_frame.pack(fill="both", expand=True, pady=8, padx=5)

        name_row = ttk.Frame(rules_frame)
        name_row.pack(fill="x", pady=(0, 5))
        ttk.Label(name_row, text="Rule name:").pack(side="left")
        self.rule_name = tk.StringVar()
        ttk.Entry(name_row, textvariable=self.rule_name, width=28).pack(side="left", padx=4)
        ttk.Button(name_row, text="Add rule", command=self._add_rule).pack(side="left", padx=8)
        ttk.Button(name_row, text="Toggle selected", command=self._toggle_rule).pack(side="left", padx=4)
        ttk.Button(name_row, text="Remove selected", command=self._remove_rule).pack(side="left", padx=4)

        match_row = ttk.Frame(rules_frame)
        match_row.pack(fill="x", pady=3)
        ttk.Label(match_row, text="Match:").pack(side="left", padx=(0, 4))
        self.rule_match = {}
        for f in _FIELD_ORDER:
            ttk.Label(match_row, text=f.upper()).pack(side="left", padx=(6, 1))
            var = tk.StringVar()
            self.rule_match[f] = var
            ttk.Entry(match_row, width=22 if f == "data" else 4, textvariable=var).pack(side="left")

        replace_row = ttk.Frame(rules_frame)
        replace_row.pack(fill="x", pady=3)
        ttk.Label(replace_row, text="Replace:").pack(side="left", padx=(0, 4))
        self.rule_replace = {}
        for f in _FIELD_ORDER:
            ttk.Label(replace_row, text=f.upper()).pack(side="left", padx=(6, 1))
            var = tk.StringVar()
            self.rule_replace[f] = var
            ttk.Entry(replace_row, width=22 if f == "data" else 4, textvariable=var).pack(side="left")

        list_row = ttk.Frame(rules_frame)
        list_row.pack(fill="both", expand=True, pady=5)
        self.rules_list = tk.Listbox(list_row, height=6)
        theme.style_listbox(self.rules_list)
        self.rules_list.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(list_row, orient="vertical", command=self.rules_list.yview)
        scroll.pack(side="right", fill="y")
        self.rules_list.configure(yscrollcommand=scroll.set)

        ttk.Label(
            rules_frame,
            text="Rules are applied only while interception is off; breakpoints scope interactive interception.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(5, 0))

    # -- interception toggle ------------------------------------------------

    def _toggle_intercept(self):
        on = self.intercept_on.get()
        self.interceptor.enabled = on
        self._sync_breakpoint()
        if on:
            self.status_label.configure(text=self._intercept_status_text())
            logging.info("APDU interception enabled")
        else:
            self.status_label.configure(text="Off — rules apply automatically")
            logging.info("APDU interception disabled")
            # Release anything currently held so an in-flight read can finish.
            if self._held is not None:
                self._resolve(self._held.original)

    def _sync_breakpoint(self):
        self.interceptor.clear_breakpoints()
        if self.breakpoint_on.get():
            match = {field: var.get().strip() for field, var in self.breakpoint_fields.items() if var.get().strip()}
            if match:
                self.interceptor.add_breakpoint(Rule(match=match, name="interactive breakpoint"))
        if self.intercept_on.get():
            self.status_label.configure(text=self._intercept_status_text())

    def _intercept_status_text(self):
        if self.breakpoint_on.get() and self.interceptor.breakpoints:
            match = self.interceptor.breakpoints[0].match
            return f"On — holding breakpoint matches {match}"
        return "On — holding every APDU"

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
        self.held_raw.set(str(apdu).upper())
        description = describe_apdu_fields(apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.lc, apdu.data, apdu.le)
        self.held_label.configure(text=f"Holding: {description}")
        self.forward_button.configure(state="normal")
        self.forward_original_button.configure(state="normal")
        self.drop_button.configure(state="normal")
        self.forge_button.configure(state="normal")

    def _clear_editor(self):
        for f in _FIELD_ORDER:
            self.fields[f].set("")
        self.held_raw.set("")
        self.held_label.configure(text="No request held.")
        self.forward_button.configure(state="disabled")
        self.forward_original_button.configure(state="disabled")
        self.drop_button.configure(state="disabled")
        self.forge_button.configure(state="disabled")

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

    def _on_forward_original(self):
        if self._held is None:
            return
        self._resolve(self._held.original)

    def _copy_held(self):
        if not self.held_raw.get():
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.held_raw.get())

    def _send_held_to_forge(self):
        if self._held is None or not hasattr(self.root, "forge_pane"):
            return
        try:
            raw = assemble_apdu(*(self.fields[field].get() for field in _FIELD_ORDER))
        except Exception:
            raw = str(self._held.original)
        label = describe_apdu_fields(
            self._held.original.cla,
            self._held.original.ins,
            self._held.original.p1,
            self._held.original.p2,
            self._held.original.lc,
            self._held.original.data,
            self._held.original.le,
        )
        self.root.forge_pane.load_apdu(raw, label=label)
        self.root.main_notebook.select(self.root.forge_tab)

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
        rule = Rule(match=match, replace=replace, name=self.rule_name.get().strip())
        self.interceptor.add_rule(rule)
        self._rules.append(rule)
        self.rules_list.insert("end", self._format_rule(rule))
        self.rule_name.set("")
        for v in self.rule_match.values():
            v.set("")
        for v in self.rule_replace.values():
            v.set("")
        logging.info(f"Added intercept rule: {rule!r}")

    @staticmethod
    def _format_rule(rule):
        state = "on" if rule.enabled else "off"
        name = f"{rule.name}: " if rule.name else ""
        return f"[{state}] {name}match {rule.match} -> replace {rule.replace}"

    def _toggle_rule(self):
        selection = self.rules_list.curselection()
        if not selection:
            return
        index = selection[0]
        rule = self._rules[index]
        rule.enabled = not rule.enabled
        self.rules_list.delete(index)
        self.rules_list.insert(index, self._format_rule(rule))
        self.rules_list.selection_set(index)
        logging.info("Intercept rule %s: %r", "enabled" if rule.enabled else "disabled", rule)

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
