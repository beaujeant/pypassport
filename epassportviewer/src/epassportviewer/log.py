import logging
import tkinter as tk
from tkinter import ttk, scrolledtext

# Single format shared by the console and the GUI log view so a line reads the
# same wherever it lands.
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"


class GuiLogHandler(logging.Handler):
    """The one bridge between the stdlib logging system and the GUI Log pane.

    Every ``pypassport`` and ``epassportviewer`` module logs through the stdlib
    ``logging`` root logger; this handler is the single place those records turn
    into text the user can see. Records are formatted once and buffered, so the
    Logs window shows the full backlog the moment it is opened, and — while a
    window is open — appended live.

    The handler keeps working with no window attached (it just buffers), which
    is also what makes it unit-testable without a running Tk main loop.
    """

    def __init__(self):
        super().__init__()
        self.records: list[str] = []
        self._widget = None  # live ScrolledText while a Logs window is open

    def emit(self, record):
        msg = self.format(record)
        self.records.append(msg)
        widget = self._widget
        if widget is not None:
            # emit() may fire from a worker thread (background reads); marshal the
            # Tk update onto the main loop via after() to stay thread-safe.
            try:
                widget.after(0, self._append, widget, msg)
            except (tk.TclError, RuntimeError):
                # Window went away between the None-check and the call.
                self._widget = None

    @staticmethod
    def _append(widget, msg):
        try:
            widget.configure(state="normal")
            widget.insert(tk.END, msg + "\n")
            widget.see(tk.END)
            widget.configure(state="disabled")
        except tk.TclError:
            pass

    def attach(self, widget):
        self._widget = widget

    def detach(self, widget):
        if self._widget is widget:
            self._widget = None


class LogPane:
    def __init__(self, root):
        self.root = root

        self.logging_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
        }

        # Install the single GUI handler on the root logger. Library logs use the
        # root logger, so this is all that is needed to route them here.
        self.handler = GuiLogHandler()
        self.handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logging.getLogger().addHandler(self.handler)
        # Keep a reference on root for the rest of the app/tests.
        self.root.log_handler = self.handler

        # "Verbose" dropdown menu
        verbose_label = ttk.Label(self.root.footer_frame, text="Log level:")
        verbose_label.pack(side=tk.LEFT, padx=(0, 5))

        self.logging_level_var = tk.StringVar(value="INFO")
        dropdown = ttk.Combobox(
            self.root.footer_frame,
            textvariable=self.logging_level_var,
            values=list(self.logging_levels.keys()),
            state="readonly",
        )
        dropdown.pack(side=tk.LEFT, padx=(0, 10))
        dropdown.bind("<<ComboboxSelected>>", self.set_logging_level)

        # "Logs" button
        logs_button = ttk.Button(self.root.footer_frame, text="Logs", command=self.open_logs_window)
        logs_button.pack(side=tk.LEFT, padx=(0, 10))

        # Version label on the right side
        version_label = ttk.Label(self.root.footer_frame, text="Version 2")
        version_label.pack(side=tk.RIGHT)

    def set_logging_level(self, event):
        selected_level = self.logging_levels.get(self.logging_level_var.get(), logging.INFO)
        logging.getLogger().setLevel(selected_level)
        logging.info(f"Logging level set to {self.logging_level_var.get()}")

    def open_logs_window(self):
        log_window = tk.Toplevel(self.root)
        log_window.title("Logs")
        log_window.geometry("600x400")

        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, state="normal")
        log_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Seed with the backlog, then stream new records live until the window
        # closes.
        for log_entry in self.handler.records:
            log_text.insert(tk.END, log_entry + "\n")
        log_text.see(tk.END)
        log_text.configure(state="disabled")

        self.handler.attach(log_text)
        log_window.protocol(
            "WM_DELETE_WINDOW",
            lambda: (self.handler.detach(log_text), log_window.destroy()),
        )
