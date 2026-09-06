from __future__ import annotations

import json
import tkinter as tk
from functools import partial
from tkinter import filedialog, messagebox, ttk


class MenuBar:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self.root.menu_bar_instance = self

        file_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        file_menu.add_command(label="Open session...", command=self.open_session)
        file_menu.add_command(label="Save session...", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.parent.close)

        self.configure_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        self.history_menu = tk.Menu(self.configure_menu, tearoff=0)
        self._populate_history_menu()

        self.configure_menu.add_cascade(label="Recent MRZ", menu=self.history_menu)
        self.configure_menu.add_command(label="Settings", command=self.open_settings)

        help_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        help_menu.add_command(label="Session file contents", command=self.show_session_help)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)

        self.root.menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.menu_bar.add_cascade(label="Configure", menu=self.configure_menu)
        self.root.menu_bar.add_cascade(label="Help", menu=help_menu)

    def _populate_history_menu(self):
        self.history_menu.delete(0, "end")
        if not self.parent.history:
            self.history_menu.add_command(label="No recent MRZ entries", state="disabled")
            return
        for entry in self.parent.history:
            self.history_menu.add_command(label=entry, command=partial(self.set_mrz, entry))

    def rebuild_history_menu(self):
        self._populate_history_menu()

    def open_session(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("ePassport session", "*.eps"), ("All files", "*.*")],
            title="Open session",
        )
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
        except (OSError, json.JSONDecodeError) as e:
            messagebox.showerror("Open failed", f"Could not read file:\n{e}")
            return
        try:
            self.parent.viewer_pane.load_snapshot(data)
        except ValueError as e:
            messagebox.showerror("Open failed", f"Invalid session file:\n{e}")
            return
        except Exception as e:
            messagebox.showerror("Open failed", f"Could not restore session:\n{e}")
            return
        # The View tab is restored by load_snapshot; refresh the Traffic tab so
        # the just-loaded (imported) history is shown and can be sent to Forge.
        self.parent.traffic_pane.reload()

    def save_session(self):
        viewer = self.parent.viewer_pane
        snapshot = viewer.get_snapshot()
        if not snapshot.get("ef_raw") and not snapshot.get("mf_ef_raw") and not snapshot.get("apdu_history"):
            messagebox.showwarning(
                "Nothing to save",
                "Read a passport or capture some APDU traffic before saving.",
            )
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".eps",
            filetypes=[("ePassport session", "*.eps"), ("All files", "*.*")],
            title="Save session",
        )
        if not file_path:
            return
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
        except OSError as e:
            messagebox.showerror("Save failed", str(e))

    def open_settings(self):
        settings = self.parent.settings

        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="CSCA certificate directory", style="Caption.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(
            frame,
            wraplength=460,
            justify="left",
            style="Muted.TLabel",
            text=(
                "Folder holding the trusted Country Signing CA (CSCA) certificates "
                "used to verify a passport's Document Signer during Passive "
                "Authentication. Download them from the issuing country's PKI "
                "(e.g. the ICAO Public Key Directory or a national master list) and "
                "point here. Accepted formats: .cer, .crt, .pem, .der, .ml."
            ),
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 10))

        path_var = tk.StringVar(value=settings.csca_dir)
        entry = ttk.Entry(frame, textvariable=path_var, width=52)
        entry.grid(row=2, column=0, sticky="ew", padx=(0, 6))

        def browse():
            chosen = filedialog.askdirectory(
                title="Select CSCA certificate directory",
                initialdir=path_var.get() or None,
                parent=dialog,
            )
            if chosen:
                path_var.set(chosen)

        ttk.Button(frame, text="Browse...", command=browse).grid(row=2, column=1, sticky="e")

        ttk.Separator(frame).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(16, 12))
        ttk.Label(frame, text="MCP", style="Caption.TLabel").grid(
            row=4, column=0, columnspan=2, sticky="w"
        )
        mcp_var = tk.BooleanVar(value=settings.mcp_enabled)
        ttk.Checkbutton(frame, text="Enable MCP", variable=mcp_var).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(4, 2)
        )
        ttk.Label(
            frame,
            wraplength=460,
            justify="left",
            style="Muted.TLabel",
            text=(
                "Allow local MCP clients such as Codex and Claude to use this "
                "viewer, its current passport session, and its selected reader."
            ),
        ).grid(row=6, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, textvariable=self.parent._mcp_status_var, style="Muted.TLabel").grid(
            row=7, column=0, columnspan=2, sticky="w", pady=(4, 0)
        )

        buttons = ttk.Frame(frame)
        buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(16, 0))

        def save_and_close():
            try:
                self.parent.set_mcp_enabled(mcp_var.get())
            except RuntimeError as exc:
                mcp_var.set(False)
                messagebox.showerror("MCP unavailable", str(exc), parent=dialog)
                return
            settings.csca_dir = path_var.get()
            dialog.destroy()

        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="Save", command=save_and_close, style="Accent.TButton").pack(side="right")

        frame.columnconfigure(0, weight=1)
        entry.focus_set()
        dialog.grab_set()
        dialog.wait_window()

    def show_session_help(self):
        messagebox.showinfo(
            "Session file contents",
            "Session files (.eps) keep the entered MRZ/CAN, captured EF bytes, "
            "APDU traffic (including wire bytes, comments, and highlights), and "
            "the Security capture context such as ATR/UID and verification results.\n\n"
            "Opening a session restores an offline capture. It does not restore "
            "a live Secure Messaging channel or session keys; read the passport "
            "again before sending new live commands.",
        )

    def show_about(self):
        messagebox.showinfo(
            "About ePassportViewer",
            "ePassportViewer v2\n\nA tool for reading and analysing ICAO 9303 ePassports.\n\nhttps://github.com/beaujeant/pypassport",
        )

    def set_mrz(self, mrz):
        mrz = mrz.strip()
        value = mrz.split(" ")
        if len(value) == 3:
            self.parent.doc_number.set(value[0])
            self.parent.dob.set(value[1])
            self.parent.expiry.set(value[2])
