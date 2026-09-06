from __future__ import annotations

import logging
import os
import queue
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
from pypassport import reader
from pypassport.doc9303.mrz import MRZ
from pypassport.epassport import EPassport
from pypassport.iso7816 import ISO7816
from epassportmcp.bridge import ViewerMCPHost
from . import theme
from .menu import MenuBar
from .operation import OperationCoordinator
from .viewer import ViewerPane
from .traffic import TrafficPane
from .forge import ForgePane
from .intercept import InterceptPane
from .analyse import AnalysePane
from .security import SecurityPane
from .log import LogPane
from .settings import Settings
from .resources.gadgets.placeholder import PlaceholderEntry


_MRZ_FIELD_NAMES = ("doc_number", "dob", "expiry")


def _credential_state(doc_number: str, dob: str, expiry: str, can: str) -> tuple[bool, set[str]]:
    """Return whether access credentials are usable and which MRZ fields are missing."""

    values = {
        "doc_number": doc_number.strip(),
        "dob": dob.strip(),
        "expiry": expiry.strip(),
        "can": can.strip(),
    }
    mrz_ready = all(values[name] for name in _MRZ_FIELD_NAMES)
    can_ready = bool(values["can"])
    if mrz_ready or can_ready:
        return True, set()
    return False, {name for name in _MRZ_FIELD_NAMES if not values[name]}


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
        self.log_entries: list[str] = []

    def emit(self, record):
        log_entry = self.format(record)
        self.log_entries.append(log_entry)


class AppRoot(tk.Tk):
    log_handler: LoggingHandler
    menu_bar: tk.Menu
    menu_bar_instance: MenuBar
    reader_combo: ttk.Combobox
    main_notebook: ttk.Notebook
    view_tab: ttk.Frame
    traffic_tab: ttk.Frame
    forge_tab: ttk.Frame
    intercept_tab: ttk.Frame
    security_tab: ttk.Frame
    footer_frame: ttk.Frame
    read_button: ttk.Button
    forge_pane: ForgePane
    security_pane: SecurityPane


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
        self.root = AppRoot()
        self.root.title("ePassportViewer")
        # Install the shared visual theme before any widget is built so every
        # pane inherits the same palette, fonts and ttk styling.
        theme.apply(self.root)
        self.root.geometry("1200x860")
        self.root.minsize(1080, 760)
        self.root.log_handler = log_handler

        ## History
        app_dir = _app_data_dir()
        app_dir.mkdir(parents=True, exist_ok=True)
        self.history_file_path = app_dir / "history"

        if not self.history_file_path.exists():
            logging.info("History file not found. Creating a new one...")
            self.history_file_path.touch()

        self.history = []
        with self.history_file_path.open("r", encoding="utf-8") as file:
            self.history = [line.strip() for line in file if line.strip()]

        ## Persistent settings (e.g. the CSCA certificate directory)
        self.settings = Settings(app_dir / "settings.json")

        ## Set environment variables
        self.reader = None
        self.iso7816 = None
        # Shared passport session, reused across every tab so reading a passport
        # once serves the View, Security, Forge, ... panes alike: its cached data
        # groups and live Secure Messaging channel are not rebuilt per action.
        # _ep_signature records the (MRZ, CAN) the session was built for so it
        # can be rebuilt when the credentials change. See get_passport().
        self.ep = None
        self._ep_signature = None
        self._reader_name = ""
        self._mcp_mrz = None
        self._mcp_can = None
        self._mcp_events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._mcp_connected = False
        self._card_busy = ""
        self._mcp_status_var = tk.StringVar(value="MCP: disabled")
        self.card_operations = OperationCoordinator(self.publish_mcp_event)

        ## Create a canvas with vertical scrollbar
        canvas = tk.Canvas(self.root, bg=theme.BACKGROUND, highlightthickness=0)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)
        main_frame = ttk.Frame(canvas, padding=(12, 8))
        main_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        content_window = canvas.create_window((0, 0), window=main_frame, anchor="nw")

        # Keep the embedded frame as wide as the canvas so panes fill the window
        # horizontally instead of collapsing to their natural width.
        def _fit_content(event):
            canvas.itemconfigure(content_window, width=event.width)
            canvas.configure(scrollregion=canvas.bbox("all"))

        canvas.bind("<Configure>", _fit_content)

        self.doc_number = tk.StringVar()
        self.dob = tk.StringVar()
        self.expiry = tk.StringVar()
        self.can = tk.StringVar()
        self._credential_entries: dict[str, PlaceholderEntry] = {}

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
        self._credential_entries["doc_number"] = PlaceholderEntry(
            mrz_frame,
            "EP123456",
            width=10,
            textvariable=self.doc_number,
        )
        self._credential_entries["doc_number"].pack(side="left")

        ttk.Label(mrz_frame, text="Date of Birth:").pack(side="left", padx=(10, 3))
        self._credential_entries["dob"] = PlaceholderEntry(mrz_frame, "YYMMDD", width=8, textvariable=self.dob)
        self._credential_entries["dob"].pack(side="left")

        ttk.Label(mrz_frame, text="Expiry Date:").pack(side="left", padx=(10, 3))
        self._credential_entries["expiry"] = PlaceholderEntry(mrz_frame, "YYMMDD", width=8, textvariable=self.expiry)
        self._credential_entries["expiry"].pack(side="left")

        # CAN (Card Access Number) — only needed for PACE-with-CAN passports
        # and eIDs. Optional: PACE-with-MRZ uses the fields above.
        ttk.Label(mrz_frame, text="CAN:").pack(side="left", padx=(10, 3))
        self._credential_entries["can"] = PlaceholderEntry(mrz_frame, "optional", width=8, textvariable=self.can)
        self._credential_entries["can"].pack(side="left")

        ### Refresh reader info
        refresh_image = Image.open(Path(__file__).parent / "resources" / "img" / "refresh.png")
        resized_image = refresh_image.resize((20, 20), resample=Image.Resampling.LANCZOS)
        self._refresh_photo = ImageTk.PhotoImage(resized_image)
        image_button = ttk.Button(mrz_frame, image=self._refresh_photo, command=self.get_reader)
        image_button.pack(side="right", padx=10)

        ### Reader dropdown
        self._reader_var = tk.StringVar()
        self.root.reader_combo = ttk.Combobox(
            mrz_frame,
            textvariable=self._reader_var,
            state="readonly",
            width=30,
        )
        self.root.reader_combo.pack(side="right", padx=(10, 0))
        self.root.reader_combo.bind("<<ComboboxSelected>>", self._on_reader_selected)

        ## Create the notebook (tabbed pane) for View, Traffic, Forge, Intercept, Security
        notebook = ttk.Notebook(main_frame)
        self.root.main_notebook = notebook
        view_tab = ttk.Frame(notebook)
        self.root.view_tab = view_tab
        traffic_tab = ttk.Frame(notebook)
        self.root.traffic_tab = traffic_tab
        forge_tab = ttk.Frame(notebook)
        self.root.forge_tab = forge_tab
        intercept_tab = ttk.Frame(notebook)
        self.root.intercept_tab = intercept_tab
        security_tab = ttk.Frame(notebook)
        self.root.security_tab = security_tab

        notebook.add(view_tab, text="View")
        notebook.add(traffic_tab, text="Traffic")
        notebook.add(forge_tab, text="Forge")
        notebook.add(intercept_tab, text="Intercept")
        notebook.add(security_tab, text="Security")
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        ### Setting up tab content
        self.viewer_pane = ViewerPane(self)
        self.traffic_pane = TrafficPane(self)
        ForgePane(self)
        InterceptPane(self)
        self.security_pane = SecurityPane(self)
        self.analyse_pane = AnalysePane(self, tab=self.security_pane.attacks_tab)

        ## Footer pane with "Verbose" dropdown, "Logs" button, and version info
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=5, padx=10)
        self.root.footer_frame = footer_frame

        LogPane(self.root)
        for variable in (self.doc_number, self.dob, self.expiry, self.can):
            variable.trace_add("write", self._on_credentials_changed)
        self._update_credential_state()
        self.get_reader()
        self.mcp_host = ViewerMCPHost(self)
        if self.settings.mcp_enabled:
            try:
                self.mcp_host.start()
                self._mcp_status_var.set("MCP: enabled")
            except RuntimeError as exc:
                self.settings.mcp_enabled = False
                self._mcp_status_var.set("MCP: unavailable")
                message = str(exc)
                self.root.after_idle(
                    lambda: messagebox.showerror("MCP unavailable", message, parent=self.root)
                )
        self.root.after(100, self._drain_mcp_events)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        # RUN THE APPLICATION
        self.root.mainloop()

    def close(self):
        """Stop the ephemeral local MCP endpoint and close the window."""

        self.mcp_host.stop()
        self.root.destroy()

    def card_operation(self, owner: str):
        return self.card_operations.operation(owner)

    def publish_mcp_event(self, kind: str, value: object) -> None:
        self._mcp_events.put((kind, value))

    def approve_mcp_action(self, action: str, effect: str) -> bool:
        request = {"action": action, "effect": effect, "event": threading.Event(), "allowed": False}
        self.publish_mcp_event("approval", request)
        return bool(request["event"].wait(300) and request["allowed"])

    def _drain_mcp_events(self):
        while True:
            try:
                kind, value = self._mcp_events.get_nowait()
            except queue.Empty:
                break
            if kind == "connected":
                self._mcp_connected = bool(value)
            elif kind == "busy":
                self._card_busy = str(value)
            elif kind == "approval" and isinstance(value, dict):
                value["allowed"] = messagebox.askyesno(
                    "MCP request",
                    f"Allow MCP action {value['action']}?\n\nCard effect: {value['effect']}",
                    parent=self.root,
                )
                value["event"].set()
            elif kind == "action" and isinstance(value, str):
                if value == "session.authenticate" and self._mcp_mrz is not None:
                    mrz = self._mcp_mrz
                    self.doc_number.set(mrz.doc_number[0])
                    self.dob.set(mrz.date_of_birth[0])
                    self.expiry.set(mrz.date_of_expiry[0])
                    if self._mcp_can is not None:
                        self.can.set(self._mcp_can)
                if value.startswith("passport.") or value.startswith("security."):
                    self.viewer_pane.refresh_from_passport()
                if value in {"apdu.clear_history", "case.import_snapshot"}:
                    self.traffic_pane.reload()
                self._update_read_button_state()
        if self._card_busy:
            self._mcp_status_var.set(f"MCP: card busy ({self._card_busy})")
        elif self._mcp_connected:
            self._mcp_status_var.set("MCP: connected")
        elif self.settings.mcp_enabled and self.mcp_host.is_running:
            self._mcp_status_var.set("MCP: enabled")
        else:
            self._mcp_status_var.set("MCP: disabled")
        self.root.after(100, self._drain_mcp_events)

    def set_mcp_enabled(self, enabled: bool) -> None:
        """Apply and persist the MCP listener setting."""

        if enabled:
            try:
                self.mcp_host.start()
            except RuntimeError:
                self.settings.mcp_enabled = False
                self._mcp_status_var.set("MCP: unavailable")
                raise
            self.settings.mcp_enabled = True
            self._mcp_status_var.set("MCP: enabled")
        else:
            self.mcp_host.stop()
            self._mcp_connected = False
            self.settings.mcp_enabled = False
            self._mcp_status_var.set("MCP: disabled")

    def add_to_history(self, doc: str, dob: str, expiry: str):
        entry = f"{doc} {dob} {expiry}"
        if entry in self.history:
            return
        self.history.append(entry)
        if len(self.history) > 20:
            self.history = self.history[-20:]
        with self.history_file_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(self.history) + "\n")
        self.root.menu_bar_instance.rebuild_history_menu()

    def _on_credentials_changed(self, *_args) -> None:
        self._update_credential_state()

    def _update_credential_state(self) -> None:
        self._mcp_can = self.can.get().strip() or None
        try:
            self._mcp_mrz = MRZ((self.doc_number.get().strip(), self.dob.get().strip(), self.expiry.get().strip()))
            if not self._mcp_mrz.check_mrz():
                self._mcp_mrz = None
        except Exception:
            self._mcp_mrz = None
        ready, missing_mrz_fields = _credential_state(
            self.doc_number.get(),
            self.dob.get(),
            self.expiry.get(),
            self.can.get(),
        )
        for name, entry in self._credential_entries.items():
            entry.set_invalid(name in missing_mrz_fields)
        self._credentials_ready = ready
        self._update_read_button_state()

    def _update_read_button_state(self) -> None:
        if not hasattr(self.root, "read_button"):
            return
        enabled = bool(self.reader) and getattr(self, "_credentials_ready", False)
        self.root.read_button.configure(state="normal" if enabled else "disabled")

    def get_reader(self):
        try:
            with self.card_operation("GUI: refresh readers"):
                return self._get_reader_unlocked()
        except Exception as exc:
            if type(exc).__name__ != "CardBusy":
                raise
            logging.warning("Could not refresh readers: %s", exc)
            messagebox.showwarning("Card busy", str(exc), parent=self.root)

    def _get_reader_unlocked(self):
        try:
            list_readers = reader.list_readers()
        except reader.ReaderException as exc:
            logging.error("%s", exc)
            list_readers = []
        combo = self.root.reader_combo
        if not list_readers:
            combo.configure(values=[], state="disabled")
            self._reader_var.set("No reader found...")
            self.reader = None
            self._update_read_button_state()
            return

        names = [str(r) for r in list_readers]
        combo.configure(values=names, state="readonly")

        # Keep current selection if still valid, otherwise default to first.
        current = self._reader_var.get()
        if current not in names:
            self._reader_var.set(names[0])

        self._connect_selected_reader()

    def _on_reader_selected(self, _event=None):
        self._connect_selected_reader()

    def _connect_selected_reader(self):
        try:
            with self.card_operation("GUI: connect reader"):
                return self._connect_selected_reader_unlocked()
        except Exception as exc:
            if type(exc).__name__ != "CardBusy":
                raise
            logging.warning("Could not switch reader: %s", exc)
            messagebox.showwarning("Card busy", str(exc), parent=self.root)

    def _connect_selected_reader_unlocked(self):
        name = self._reader_var.get()
        self.reader = reader.get_reader(name)
        # (Re)connecting a reader resets the card, so any shared passport
        # session and its Secure Messaging channel are no longer valid.
        self.ep = None
        self._ep_signature = None
        self.iso7816 = None
        self._reader_name = name
        if not self.reader:
            self._update_read_button_state()
            return

        reader_name = self.reader.getReader()
        try:
            self.reader.connect()
        except Exception as exc:
            if reader.is_no_card_exception(exc):
                logging.warning("Reader %r found, but no card is inserted.", reader_name)
            elif reader.is_card_connection_exception(exc):
                logging.error("Could not connect to card on reader %r: %s", reader_name, exc)
            else:
                logging.exception("Unexpected reader connection failure on %r", reader_name)
            self._update_read_button_state()
            return

        self._update_read_button_state()
        self.iso7816 = ISO7816(self.reader)

    def get_passport(self, mrz, can, *, force_new=False):
        """Return the shared L{EPassport} session, (re)building it when needed.

        The whole application works off a single passport object so that a read
        on one tab is reused everywhere: its data groups stay cached and its
        Secure Messaging channel (BAC/PACE) stays live, instead of every action
        re-running access control and re-reading the chip. The session's
        C{iso7816} is published as the shared channel so the Forge / Intercept
        tabs keep operating on the same connection.

        A fresh session is built when there is none yet, when the credentials
        differ from the ones the current session was built for, or when
        C{force_new} is set (the View tab's Read button uses this so an explicit
        Read always re-fetches from the chip). Otherwise the existing session is
        returned untouched.

        @param mrz: The C{(number, dob, expiry)} tuple, or None when only a CAN
            is supplied.
        @param can: The Card Access Number string, or None.
        @param force_new: Force a brand-new session even if one already matches.
        @return: The shared L{EPassport}. It is connected but not necessarily
            opened; call L{EPassport.open}/L{EPassport.ensure_open} to set up
            Secure Messaging.
        @raise EPassportException: If the session cannot be created.
        """
        signature = (tuple(mrz) if mrz else None, can)
        if not force_new and self.ep is not None and self._ep_signature == signature:
            return self.ep
        ep = EPassport(self.reader, mrz, select_aid=False)
        # This is the canonical read channel; its traffic shows up as "read"
        # unless another tab (Forge, Security) relabels it while it drives.
        ep.iso7816.source = "read"
        self.ep = ep
        self._ep_signature = signature
        self.iso7816 = ep.iso7816
        return ep

    def ensure_iso7816(self):
        """Return the shared ISO7816 transport, creating it on demand.

        Tabs that talk to the chip without first reading a passport (Forge,
        Security) share one channel through here, so they operate on the same
        connection — and the same live Secure Messaging session — as the View
        tab instead of each spinning up their own.
        """
        if not self.iso7816:
            self.iso7816 = ISO7816(self.reader)
        return self.iso7816


if __name__ == "__main__":
    EPassportViewer()
