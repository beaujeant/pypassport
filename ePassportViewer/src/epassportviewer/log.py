import logging
import tkinter as tk
from tkinter import ttk, scrolledtext


class LogPane:
    def __init__(self, root):
        self.root = root

        self.logging_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
        }

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

    # Function to open the logs window and periodically refresh the content
    def open_logs_window_2(self):
        log_window = tk.Toplevel(self.root)
        log_window.title("Logs")
        log_window.geometry("400x300")

        log_text = tk.Text(log_window, wrap="word", state="disabled")
        log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Function to read and display the contents of the log file
        def update_log_content():
            try:
                with open("ep.logs", "r") as log_file:
                    content = log_file.read()
                log_text.config(state="normal")
                log_text.delete(1.0, tk.END)
                log_text.insert(tk.END, content)
                log_text.config(state="disabled")
            except FileNotFoundError:
                log_text.config(state="normal")
                log_text.delete(1.0, tk.END)
                log_text.insert(tk.END, "Log file not found.")
                log_text.config(state="disabled")

            # Schedule the update function to run every 1000 ms (1 second)
            log_window.after(1000, update_log_content)

        update_log_content()  # Initial call to load content

    def open_logs_window(self):
        log_window = tk.Toplevel(self.root)
        log_window.title("Logs")
        log_window.geometry("600x400")

        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, state="normal")
        log_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Add logs to the text box
        for log_entry in self.root.log_handler.log_entries:
            log_text.insert(tk.END, log_entry + "\n")

        log_text.configure(state="disabled")
