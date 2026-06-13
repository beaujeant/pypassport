import json
import tkinter as tk
from tkinter import filedialog, messagebox


class MenuBar:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self.root.menu_bar_instance = self

        file_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        file_menu.add_command(label="Open session", command=self.open_file)
        file_menu.add_command(label="Save session", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        self.configure_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        self.history_menu = tk.Menu(self.configure_menu, tearoff=0)
        self._populate_history_menu()

        self.configure_menu.add_cascade(label="History", menu=self.history_menu)
        self.configure_menu.add_command(label="Settings", command=self.open_settings)

        help_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)

        self.root.menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.menu_bar.add_cascade(label="Configure", menu=self.configure_menu)
        self.root.menu_bar.add_cascade(label="Help", menu=help_menu)

    def _populate_history_menu(self):
        self.history_menu.delete(0, "end")
        for entry in self.parent.history:
            self.history_menu.add_command(label=entry, command=lambda mrz=entry: self.setMRZ(mrz))

    def rebuild_history_menu(self):
        self._populate_history_menu()

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("ePassport session", "*.eps"), ("All files", "*.*")],
            title="Open session",
        )
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = f.read()
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as e:
            messagebox.showerror("Open failed", f"Could not read file:\n{e}")
            return
        try:
            self.parent.viewer_pane.load_snapshot(data)
        except ValueError as e:
            messagebox.showerror("Open failed", f"Invalid session file:\n{e}")
        except Exception as e:
            messagebox.showerror("Open failed", f"Could not restore session:\n{e}")

    def save_file(self):
        viewer = self.parent.viewer_pane
        snapshot = viewer.get_snapshot()
        # Worth saving if anything was captured — a passport read or any APDU
        # traffic. Only an entirely empty session is rejected.
        if not snapshot.get("ef_raw") and not snapshot.get("apdu_history"):
            messagebox.showwarning(
                "Nothing to save",
                "Read a passport or capture some APDU traffic before saving a session.",
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
        messagebox.showinfo("Settings", "No configurable settings at this time.")

    def show_about(self):
        messagebox.showinfo(
            "About ePassportViewer",
            "ePassportViewer v2\n\nA tool for reading and analysing ICAO 9303 ePassports.\n\nhttps://github.com/beaujeant/pypassport",
        )

    def setMRZ(self, mrz):
        mrz = mrz.strip()
        value = mrz.split(" ")
        if len(value) == 3:
            self.parent.doc_number.set(value[0])
            self.parent.dob.set(value[1])
            self.parent.expiry.set(value[2])
