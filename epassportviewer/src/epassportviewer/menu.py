import tkinter as tk
from tkinter import filedialog, messagebox


class MenuBar:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        file_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        configure_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        history_menu = tk.Menu(configure_menu, tearoff=0)

        for line in main.history:
            line = line.strip()
            history_menu.add_command(label=line, command=lambda mrz=line: self.setMRZ(mrz))

        if main.history:
            self.setMRZ(main.history[-1])

        configure_menu.add_cascade(label="History", menu=history_menu)
        configure_menu.add_command(label="Settings", command=self.open_settings)

        help_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)

        self.root.menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.menu_bar.add_cascade(label="Configure", menu=configure_menu)
        self.root.menu_bar.add_cascade(label="Help", menu=help_menu)

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Open MRZ file",
        )
        if file_path:
            try:
                with open(file_path, "r") as f:
                    content = f.read().strip()
                self.setMRZ(content)
            except Exception as e:
                messagebox.showerror("Open failed", str(e))

    def save_file(self):
        doc = self.parent.doc_number.get()
        dob = self.parent.dob.get()
        expiry = self.parent.expiry.get()
        if not (doc and dob and expiry):
            messagebox.showwarning("Nothing to save", "Fill in the MRZ fields before saving.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save MRZ",
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(f"{doc} {dob} {expiry}\n")
            except Exception as e:
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
