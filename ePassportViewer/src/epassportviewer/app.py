import logging
from pathlib import Path
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
from pypassport import reader
from .menu import MenuBar
from .viewer import ViewerPane
from .attacks import AttacksPane
from .custom import CustomPane
from .log import LogPane
from .resources.gadgets.placeholder import PlaceholderEntry


class LoggingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.log_entries = []

    def emit(self, record):
        log_entry = self.format(record)
        self.log_entries.append(log_entry)


class EPassportViewer():
    def __init__(self):
        # CONFIGURATION
        ## Logging
        log_handler = LoggingHandler()
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(), log_handler]
        )


        # BUILDING UI
        ## Initialize the main window
        self.root = tk.Tk()
        self.root.title("ePassportViewer")
        self.root.geometry("915x775")
        self.root.minsize(915, 775)
        self.root.log_handler = log_handler


        ## History
        HISTORY_FILE_NAME = "history"
        APP_FOLDER = Path(__file__).parent
        HISTORY_FILE_PATH = APP_FOLDER / HISTORY_FILE_NAME

        if not HISTORY_FILE_PATH.exists():
            logging.info("Histmicro pythonory file not found. Creating a new one...")
            HISTORY_FILE_PATH.touch()

        self.history = []
        with HISTORY_FILE_PATH.open("r") as file:
            self.history = file.readlines()

        ## Set environment variables
        self.reader = None
        self.iso7816 = None


        ## Create a canvas with vertical scrollbar
        canvas = tk.Canvas(self.root)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        main_frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=main_frame, anchor="nw")

        self.doc_number = tk.StringVar()
        self.dob = tk.StringVar()
        self.expiry = tk.StringVar()

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

        ### Refresh reader info
        image = Image.open(Path(__file__).parent / "resources" / "img" / "refresh.png")
        image = image.resize((20, 20), resample=Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_button = tk.Button(mrz_frame, image=photo, command=self.get_reader)
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


    def get_reader(self):
        self.reader = reader.getReader()
        if self.reader:
            self.reader.connect()
            self.root.reader_info_label["text"] = f"Reader found: {self.reader.getReader()}"
            self.root.read_button["state"] = "normal"
        else:
            self.root.reader_info_label["text"] = "No reader found..."
            self.root.read_button["state"] = "disabled"


if __name__ == "__main__":
    EPassportViewer()
