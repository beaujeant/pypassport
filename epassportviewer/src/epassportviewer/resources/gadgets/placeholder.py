import tkinter as tk
from tkinter import ttk


class PlaceholderEntry(ttk.Entry):
    """ttk.Entry that shows greyed-out placeholder text when empty and unfocused.

    The placeholder is purely visual: while it is displayed, the linked
    ``textvariable`` is detached so the placeholder string never leaks into
    the caller's StringVar. A trace on the variable reattaches it if external
    code assigns a value while the placeholder is showing.
    """

    def __init__(self, parent, placeholder, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.placeholder = placeholder
        self.placeholder_color = "grey"
        self.default_color = "black"

        self._textvariable = kwargs.get("textvariable")
        self._is_placeholder = False

        if self._textvariable is not None:
            self._textvariable.trace_add("write", self._on_var_write)

        self._show_placeholder()

        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._show_placeholder)

    def _show_placeholder(self, event=None):
        if self._is_placeholder or self.get():
            return
        self._is_placeholder = True
        if self._textvariable is not None:
            # Detach the StringVar so writing the placeholder text into the
            # entry doesn't propagate to caller code.
            self.configure(textvariable="")
        self.configure(foreground=self.placeholder_color)
        self.insert(0, self.placeholder)

    def _clear_placeholder(self, event=None):
        if not self._is_placeholder:
            return
        self.delete(0, tk.END)
        self.configure(foreground=self.default_color)
        if self._textvariable is not None:
            self.configure(textvariable=self._textvariable)
        self._is_placeholder = False

    def _on_var_write(self, *args):
        if self._is_placeholder and self._textvariable.get():
            self._clear_placeholder()
