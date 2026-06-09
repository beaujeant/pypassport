import logging
import os
import sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
from smartcard.Exceptions import CardConnectionException, NoCardException
from pypassport import reader
from .menu import MenuBar
from .viewer import ViewerPane
from .attacks import AttacksPane
from .custom import CustomPane
from .log import LogPane
from .resources.gadgets.placeholder import PlaceholderEntry


def _app_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "epassportviewer"


class LoggingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.log_entries = []

    def emit(self, record):
        log_entry = self.format(record)
        self.log_entries.append(log_entry)


class EPassportViewer:
    def __init__(self):
        # CONFIGURATION
        ## Logging
        log_handler = LoggingHandler()
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(), log_handler],
        )

        # BUILDING UI
        ## Initialize the main window
        self.root = tk.Tk()
        self.root.title("ePassportViewer")
        self.root.geometry("915x775")
        self.root.minsize(915, 775)
        self.root.log_handler = log_handler

        ## History
        app_dir = _app_data_dir()
        app_dir.mkdir(parents=True, exist_ok=True)
        self.history_file_path = app_dir / "history"

        if not self.history_file_path.exists():
            logging.info("History file not found. Creating a new one...")
            self.history_file_path.touch()

        self.history = []
        with self.history_file_path.open("r") as file:
            self.history = [line.strip() for line in file if line.strip()]

        ## Set environment variables
        self.reader = None
        self.iso7816 = None

        ## Create a canvas with vertical scrollbar
        style = ttk.Style()
        theme_bg = style.lookup("TFrame", "background")
        canvas = tk.Canvas(self.root, bg=theme_bg, highlightthickness=0)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        main_frame = ttk.Frame(canvas)
        main_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=main_frame, anchor="nw")

        self.doc_number = tk.StringVar()
        self.dob = tk.StringVar()
        self.expiry = tk.StringVar()
        self.can = tk.StringVar()

        ## Create menu bar
        menu_bar = tk.Menu(self.root)
        self.root.menu_bar = menu_bar
        MenuBar(self)
        self.root.config(menu=menu_bar)

        ## MRZ input bar
        mrz_frame = ttk.Frame(main_frame, height=50)
        mrz_frame.pack(fill="x", pady=5)

        ### Add the input fields to MRZ input bar
        ttk.Label(mrz_frame, text="Number:").pack(side="left", padx=(5, 3))
        PlaceholderEntry(mrz_frame, "EP123456", width=10, textvariable=self.doc_number).pack(side="left")

        ttk.Label(mrz_frame, text="Date of Birth:").pack(side="left", padx=(10, 3))
        PlaceholderEntry(mrz_frame, "YYMMDD", width=8, textvariable=self.dob).pack(side="left")

        ttk.Label(mrz_frame, text="Expiry Date:").pack(side="left", padx=(10, 3))
        PlaceholderEntry(mrz_frame, "YYMMDD", width=8, textvariable=self.expiry).pack(side="left")

        # CAN (Card Access Number) — only needed for PACE-with-CAN passports
        # and eIDs. Optional: PACE-with-MRZ uses the fields above.
        ttk.Label(mrz_frame, text="CAN:").pack(side="left", padx=(10, 3))
        PlaceholderEntry(mrz_frame, "optional", width=8, textvariable=self.can).pack(side="left")

        ### Refresh reader info
        image = Image.open(Path(__file__).parent / "resources" / "img" / "refresh.png")
        image = image.resize((20, 20), resample=Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_button = ttk.Button(mrz_frame, image=photo, command=self.get_reader)
        image_button.image = photo
        image_button.pack(side="right", padx=10)

        ### Reader info
        self.root.reader_info_label = ttk.Label(mrz_frame, text="No reader found...")
        self.root.reader_info_label.pack(side="right")

        ## Create the notebook (tabbed pane) for View, Attacks, Custom
        notebook = ttk.Notebook(main_frame)
        view_tab = ttk.Frame(notebook)
        self.root.view_tab = view_tab
        attacks_tab = ttk.Frame(notebook)
        self.root.attacks_tab = attacks_tab
        custom_tab = ttk.Frame(notebook)
        self.root.custom_tab = custom_tab

        notebook.add(view_tab, text="View")
        notebook.add(attacks_tab, text="Attacks")
        notebook.add(custom_tab, text="Custom")
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        ### Setting up the View tab content for the passport display
        ViewerPane(self)
        AttacksPane(self)
        CustomPane(self)

        ## Footer pane with "Verbose" dropdown, "Logs" button, and version info
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=5, padx=10)
        self.root.footer_frame = footer_frame

        LogPane(self.root)
        self.get_reader()

        # RUN THE APPLICATION
        self.root.mainloop()

    def add_to_history(self, doc: str, dob: str, expiry: str):
        entry = f"{doc} {dob} {expiry}"
        if entry in self.history:
            return
        self.history.append(entry)
        if len(self.history) > 20:
            self.history = self.history[-20:]
        with self.history_file_path.open("w") as f:
            f.write("\n".join(self.history) + "\n")
        self.root.menu_bar_instance.rebuild_history_menu()

    def get_reader(self):
        self.reader = reader.getReader()
        if not self.reader:
            self.root.reader_info_label["text"] = "No reader found..."
            self.root.read_button["state"] = "disabled"
            return

        reader_name = self.reader.getReader()
        try:
            self.reader.connect()
        except NoCardException:
            logging.warning(f"Reader '{reader_name}' found, but no card is inserted.")
            self.root.reader_info_label["text"] = f"Reader: {reader_name} (no card)"
            self.root.read_button["state"] = "normal"
            return
        except CardConnectionException as e:
            logging.error(f"Could not connect to card on reader '{reader_name}': {e}")
            self.root.reader_info_label["text"] = f"Reader: {reader_name} (connection error)"
            self.root.read_button["state"] = "normal"
            return

        self.root.reader_info_label["text"] = f"Reader found: {reader_name}"
        self.root.read_button["state"] = "normal"


if __name__ == "__main__":
    EPassportViewer()
