import tkinter as tk
from tkinter import ttk

class MenuBar:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        file_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        file_menu.add_command(label="Open")
        file_menu.add_command(label="Save")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        configure_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        history_menu = tk.Menu(file_menu, tearoff=0)

        for line in main.history:
            line = line.strip()
            history_menu.add_command(label=line, command=lambda mrz=line: self.setMRZ(mrz))

        if main.history:
            self.setMRZ(main.history[-1])
    
        configure_menu.add_cascade(label="History", menu=history_menu)
        configure_menu.add_command(label="Settings")

        help_menu = tk.Menu(self.root.menu_bar, tearoff=0)
        help_menu.add_command(label="About")

        self.root.menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.menu_bar.add_cascade(label="Configure", menu=configure_menu)
        self.root.menu_bar.add_cascade(label="Help", menu=help_menu)


    def setMRZ(self, mrz):
        mrz = mrz.strip()
        value = mrz.split(" ")
        if len(value) == 3:
            self.parent.doc_number.set(value[0])
            self.parent.dob.set(value[1])
            self.parent.expiry.set(value[2])