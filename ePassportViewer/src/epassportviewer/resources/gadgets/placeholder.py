import tkinter as tk
from tkinter import ttk


class PlaceholderEntry(ttk.Entry):
    def __init__(self, parent, placeholder, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.placeholder = placeholder
        self.placeholder_color = "grey"
        self.default_color = "black"

        # Add the placeholder text
        self.show_placeholder()

        # Bind events to manage focus behavior
        self.bind("<FocusIn>", self.clear_placeholder)
        self.bind("<FocusOut>", self.show_placeholder)

    def show_placeholder(self, event=None):
        """Show the placeholder text if the entry is empty."""
        if not self.get():
            self.configure(foreground=self.placeholder_color)
            self.insert(0, self.placeholder)

    def clear_placeholder(self, event=None):
        """Clear the placeholder text if it's displayed."""
        if self.get() == self.placeholder:
            self.delete(0, tk.END)
            self.configure(foreground=self.default_color)
