import logging
import io
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
from tkinter import messagebox
from pypassport.epassport import EPassport, EPassportException
from pypassport.iso7816 import APDUCommand
from pypassport.apdu_history import APDUHistory
from pypassport.doc9303.data_group import _CLASS_MAP
from pypassport.doc9303 import converter as dg_converter


# Bump whenever the on-disk session layout changes. There is no backward
# compatibility: a file written by another version simply fails to load.
SESSION_VERSION = 3
# Panes that may stash free-form scratch state in a saved session. Each, when
# present, exposes get_scratch()/load_scratch(); both are optional so a session
# round-trips cleanly whether or not the pane is built or has state.
_SCRATCH_PANES = ("sequencer",)


# Row 1: file-system / meta EFs in logical access order
_ROW1 = ["ATR/INFO", "DIR", "CardAccess", "COM", "SOD"]
# Row 2: DG1–DG8
_ROW2 = ["DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7", "DG8"]
# Row 3: DG9–DG16
_ROW3 = ["DG9", "DG10", "DG11", "DG12", "DG13", "DG14", "DG15", "DG16"]
_EF_NAMES = _ROW1 + _ROW2 + _ROW3


class ViewerPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root

        # Inner menu frame
        reader_info = ttk.Frame(self.root.view_tab)
        reader_info.pack(fill="x", pady=10, padx=10)

        # "Read" button
        self.root.read_button = ttk.Button(reader_info, text="Read", command=self.read_passport)
        self.root.read_button.pack(side="left", padx=5)

        # Top section: photo + passport info side by side
        top_frame = ttk.Frame(self.root.view_tab)
        top_frame.pack(fill="x", padx=10, anchor="n")

        # Left side for image
        image_frame = ttk.Frame(top_frame, width=200, height=300)
        image_frame.pack(side="left", padx=10, anchor="n")

        # Placeholder for the passport photo
        self.passport_photo = tk.Label(
            image_frame, text="Passport Photo\n(200px x 300px)", relief="solid", width=25, height=15
        )
        self.passport_photo.pack(padx=5, pady=5)

        # Right side for textual information
        info_frame = ttk.Frame(top_frame)
        info_frame.pack(side="left", pady=5, anchor="n")

        # Define labels for each field in 3 columns
        self.fields = {}
        default_val = "None"

        ttk.Label(info_frame, text="Type", font=("", 10, "bold")).grid(row=0, column=0, sticky="w", padx=(5, 300))
        self.fields["type"] = ttk.Label(info_frame, text=default_val)
        self.fields["type"].grid(row=1, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Surame", font=("", 10, "bold")).grid(row=2, column=0, sticky="w", padx=5)
        self.fields["surname"] = ttk.Label(info_frame, text=default_val)
        self.fields["surname"].grid(row=3, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Name", font=("", 10, "bold")).grid(row=4, column=0, sticky="w", padx=5)
        self.fields["name"] = ttk.Label(info_frame, text=default_val)
        self.fields["name"].grid(row=5, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Nationality", font=("", 10, "bold")).grid(row=6, column=0, sticky="w", padx=5)
        self.fields["nationality"] = ttk.Label(info_frame, text=default_val)
        self.fields["nationality"].grid(row=7, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Date of Birth", font=("", 10, "bold")).grid(row=8, column=0, sticky="w", padx=5)
        self.fields["dob"] = ttk.Label(info_frame, text=default_val)
        self.fields["dob"].grid(row=9, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Signature", font=("", 10, "bold")).grid(row=10, column=0, sticky="w", padx=5)
        self.fields["signature"] = ttk.Label(info_frame, text=default_val)
        self.fields["signature"].grid(row=11, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Passport Number", font=("", 10, "bold")).grid(row=0, column=1, sticky="w", padx=5)
        self.fields["number"] = ttk.Label(info_frame, text=default_val)
        self.fields["number"].grid(row=1, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Issuing Country", font=("", 10, "bold")).grid(row=2, column=1, sticky="w", padx=5)
        self.fields["country"] = ttk.Label(info_frame, text=default_val)
        self.fields["country"].grid(row=3, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Sex", font=("", 10, "bold")).grid(row=4, column=1, sticky="w", padx=5)
        self.fields["sex"] = ttk.Label(info_frame, text=default_val)
        self.fields["sex"].grid(row=5, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Date of Expiry", font=("", 10, "bold")).grid(row=6, column=1, sticky="w", padx=5)
        self.fields["expiry"] = ttk.Label(info_frame, text=default_val)
        self.fields["expiry"].grid(row=7, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Optional Data", font=("", 10, "bold")).grid(row=8, column=1, sticky="w", padx=5)
        self.fields["optional"] = ttk.Label(info_frame, text=default_val)
        self.fields["optional"].grid(row=9, column=1, sticky="w", pady=(4, 10), padx=5)

        # EF panel: two-row custom tab bar + shared content area
        ef_panel = ttk.Frame(self.root.view_tab)
        ef_panel.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        # Two-row button bar — each row is a separate frame so buttons in
        # each row are sized equally within that row while both rows share
        # the same total width.
        tab_bar = ttk.Frame(ef_panel, relief="groove", borderwidth=1)
        tab_bar.pack(fill="x")

        self._ef_buttons = {}
        self._ef_contents = {}   # ef_name -> str content or None
        self._ef_inaccessible = set()  # EFs advertised in EF.COM but unreadable
        self._selected_ef = None
        self._photo_bytes = None  # raw image bytes from DG2, kept for Save

        style = ttk.Style()
        style.configure("EFTab.TButton", font=("", 8), padding=(4, 2))
        style.configure("EFTabActive.TButton", font=("", 8, "bold"), padding=(4, 2))
        style.configure("EFTabInaccessible.TButton", font=("", 8, "italic"), padding=(4, 2))
        style.configure("EFTabInaccessibleActive.TButton", font=("", 8, "bold italic"), padding=(4, 2))

        for row_index, row_efs in enumerate((_ROW1, _ROW2, _ROW3)):
            row_frame = ttk.Frame(tab_bar)
            row_frame.pack(fill="x", side="top")
            for ef in row_efs:
                btn = ttk.Button(
                    row_frame, text=ef, style="EFTab.TButton",
                    state="disabled", command=lambda e=ef: self._select_ef(e),
                )
                btn.pack(side="left", padx=1, pady=1)
                self._ef_buttons[ef] = btn

        # Shared content area
        content_frame = ttk.Frame(ef_panel, relief="sunken", borderwidth=1)
        content_frame.pack(fill="both", expand=True)

        self._ef_text = tk.Text(
            content_frame, wrap="word", state="disabled",
            font=("Courier", 9), height=8,
        )
        self._ef_text_default_fg = self._ef_text.cget("foreground")
        scroll = ttk.Scrollbar(content_frame, orient="vertical", command=self._ef_text.yview)
        self._ef_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._ef_text.pack(side="left", fill="both", expand=True)

    def _select_ef(self, ef):
        self._selected_ef = ef
        content = self._ef_contents.get(ef)
        self._ef_text.configure(state="normal")
        self._ef_text.delete("1.0", "end")
        if content:
            self._ef_text.insert("end", content)
        self._ef_text.configure(state="disabled")
        for name, btn in self._ef_buttons.items():
            if self._ef_contents.get(name) is not None:
                inaccessible = name in self._ef_inaccessible
                if name == ef:
                    btn.configure(style="EFTabInaccessibleActive.TButton" if inaccessible else "EFTabActive.TButton")
                else:
                    btn.configure(style="EFTabInaccessible.TButton" if inaccessible else "EFTab.TButton")

    def _reset_ef_tabs(self):
        self._selected_ef = None
        self._ef_contents = {ef: None for ef in _EF_NAMES}
        self._ef_inaccessible = set()
        self._photo_bytes = None
        self._ef_raw = {}
        self._mf_ef_raw = {}
        for btn in self._ef_buttons.values():
            btn.configure(state="disabled", style="EFTab.TButton")
        self._ef_text.configure(state="normal")
        self._ef_text.delete("1.0", "end")
        self._ef_text.configure(state="disabled")

    def _set_ef_content(self, ef, content, inaccessible=False):
        self._ef_contents[ef] = content
        if inaccessible:
            self._ef_inaccessible.add(ef)
        else:
            self._ef_inaccessible.discard(ef)
        btn = self._ef_buttons[ef]
        if content is not None:
            style = "EFTabInaccessible.TButton" if inaccessible else "EFTab.TButton"
            btn.configure(state="normal", style=style)
            if self._selected_ef == ef:
                self._select_ef(ef)
        else:
            btn.configure(state="disabled", style="EFTab.TButton")

    def _ef_to_str(self, ef_name, data):
        if data is None:
            return None
        try:
            return str(data)
        except Exception:
            return repr(data)

    @staticmethod
    def _read_mf_ef(iso7816, fid):
        """Read a Master-File-level EF by FID before the eMRTD AID is selected.

        Returns the raw bytes as an upper-case hex string, or None on failure.
        Tries progressively smaller read sizes to cope with cards that raise
        6282 (EOF) when Le exceeds the file length.
        """
        # Explicitly select the MF so this works even if a previous read left
        # the card on a different DF (e.g. the eMRTD application DF).
        try:
            iso7816.transmit(APDUCommand("00", "A4", "00", "0C", data="3F00"), "Select MF")
        except Exception:
            pass
        try:
            iso7816.selectElementaryFile(fid)
        except Exception:
            return None
        for size in (0xDF, 0x7F, 0x3F, 0x1F, 0x0F, 0x04):
            try:
                data = iso7816.readBinary(0, size)
                return data.hex().upper()
            except Exception:
                continue
        return None

    def read_passport(self):
        doc_number = self.parent.doc_number.get()
        dob = self.parent.dob.get()
        expiry = self.parent.expiry.get()
        can = self.parent.can.get().strip() or None

        mrz_supplied = bool(doc_number and dob and expiry)
        if not mrz_supplied and not can:
            messagebox.showerror(
                "Passport read failed",
                "Enter the MRZ (Number + DoB + Expiry) and/or a CAN.",
            )
            return

        try:
            logging.info(f"{doc_number} {dob} {expiry}" + (f" CAN={can}" if can else ""))
            ep = EPassport(
                self.parent.reader,
                (doc_number, dob, expiry) if mrz_supplied else None,
                select_aid=False,
            )
            # Read MF-level files now, before ep.open() selects the eMRTD AID.
            # Attempting to select these FIDs (2F01, 2F00) after AID selection
            # can deselect the eMRTD application on many cards.
            mf_ef_raw = {
                "ATR/INFO": self._read_mf_ef(ep.iso7816, "2F01"),
                "DIR":      self._read_mf_ef(ep.iso7816, "2F00"),
            }
            result = ep.open(can=can)
            logging.info(f"Access control: {result.mechanism}")
            # Publish this session's iso7816 (carrying the BAC/PACE Secure
            # Messaging context and its live SSC counter) as the shared one so
            # the Forge, Sequencer and other tabs operate on the same channel.
            self.parent.iso7816 = ep.iso7816
        except EPassportException as e:
            logging.error(f"Could not initialize ePassport session: {e}")
            messagebox.showerror("Passport read failed", str(e))
            return
        except Exception as e:
            logging.exception("Unexpected error while initializing ePassport session")
            messagebox.showerror(
                "Passport read failed",
                f"Unexpected error while connecting to the passport: {e}",
            )
            return

        try:
            dg1 = ep["DG1"]
        except EPassportException as e:
            logging.error(f"Could not read DG1: {e}")
            messagebox.showerror("Passport read failed", str(e))
            return
        except Exception as e:
            logging.exception("Unexpected error while reading DG1")
            messagebox.showerror(
                "Passport read failed",
                f"Unexpected error while reading DG1: {e}",
            )
            return

        if dg1 is None:
            messagebox.showerror(
                "Passport read failed",
                "DG1 could not be read from the chip. Check the MRZ and try again.",
            )
            return

        try:
            self.fields["type"].configure(text=dg1["5F1F"]["5F03"].replace("<", " ").strip())
            self.fields["country"].configure(text=dg1["5F1F"]["5F28"].replace("<", " ").strip())
            name = dg1["5F1F"]["5F5B"].split("<<")
            self.fields["surname"].configure(text=name[0].replace("<", " ").strip())
            self.fields["name"].configure(text=name[1].replace("<", " ").strip() if len(name) > 1 else "")
            self.fields["number"].configure(text=dg1["5F1F"]["5A"].replace("<", " ").strip())
            self.fields["nationality"].configure(text=dg1["5F1F"]["5F2C"].replace("<", " ").strip())
            self.fields["dob"].configure(text=dg1["5F1F"]["5F57"].replace("<", " ").strip())
            self.fields["sex"].configure(text=dg1["5F1F"]["5F35"].replace("<", " ").strip())
            self.fields["expiry"].configure(text=dg1["5F1F"]["59"].replace("<", " ").strip())
            self.fields["optional"].configure(text=dg1["5F1F"]["53"].replace("<", " ").strip())
        except (KeyError, AttributeError) as e:
            logging.exception("Could not parse DG1 fields")
            messagebox.showerror(
                "Passport read failed",
                f"Could not parse DG1 fields (unexpected layout): {e}",
            )
            return

        if doc_number and dob and expiry:
            self.parent.add_to_history(doc_number, dob, expiry)

        # Populate EF tabs
        self._reset_ef_tabs()
        self._mf_ef_raw = {k: v for k, v in mf_ef_raw.items() if v is not None}
        self._ef_raw["DG1"] = dg1.file.hex()

        try:
            dg2 = ep["DG2"]
            if dg2 is None:
                raise EPassportException("DG2 could not be read from the chip.")
            self._photo_bytes = bytes(dg2["7F61"][0]["7F60"]["5F2E"])
            self._display_photo(self._photo_bytes)
        except EPassportException as e:
            logging.error(f"Could not read DG2: {e}")
            messagebox.showerror("Passport photo unavailable", str(e))
        except Exception as e:
            logging.exception("Could not load passport photo from DG2")
            messagebox.showerror(
                "Passport photo unavailable",
                f"Could not load the passport photo: {e}",
            )
        for ef in _EF_NAMES:
            # DG1 is guaranteed readable — use the already-parsed local variable
            # so a failed re-read attempt never clears the tab.
            if ef == "DG1":
                self._set_ef_content("DG1", self._ef_to_str("DG1", dg1))
                continue

            # ATR/INFO and DIR live in the MF, not the eMRTD DF.  They were
            # read via raw ISO7816 before ep.open() selected the eMRTD AID.
            if ef in mf_ef_raw:
                self._set_ef_content(ef, mf_ef_raw[ef])
                continue

            try:
                data = ep[ef]
            except Exception as e:
                logging.warning(f"Could not read {ef}: {e}")
                self._set_ef_content(ef, None)
                continue
            if data is None:
                logging.warning(f"{ef} returned None (chip read or parsing failed)")
                self._set_ef_content(ef, None)
                continue
            if hasattr(data, "file"):
                self._ef_raw[ef] = data.file.hex()
            try:
                content = self._ef_to_str(ef, data)
            except Exception as e:
                logging.warning(f"Could not stringify {ef}: {e}")
                content = f"(Could not display {ef}: {e})"
            self._set_ef_content(ef, content)

        # Cross-reference EF.COM tag list: enable tabs for DGs the chip
        # advertises (5C list) but that couldn't be read, so the user can
        # see they are present rather than silently disabled.
        try:
            com = ep["COM"]
            advertised_tags = com.get("5C", []) if com else []
        except Exception:
            advertised_tags = []
        for tag_hex in advertised_tags:
            try:
                from pypassport.doc9303.converter import toDG
                ef_name = toDG(tag_hex)
            except Exception:
                continue
            if ef_name in self._ef_buttons and self._ef_contents.get(ef_name) is None:
                self._set_ef_content(
                    ef_name,
                    f"{ef_name} is listed in EF.COM but could not be read — "
                    f"the chip may require Active Authentication or another "
                    f"access condition before granting access.",
                    inaccessible=True,
                )

        self._select_ef("DG1")

    def update_field(self, item, value):
        self.fields[item].config(text=value)

    # ------------------------------------------------------------------ #
    # Snapshot: save / restore all read data without touching the chip     #
    # ------------------------------------------------------------------ #

    def get_snapshot(self) -> dict:
        """Return a JSON-serialisable dict capturing the whole research session.

        Beyond the raw EF bytes shown in the View tab this includes the MRZ/CAN
        credentials, the full APDU history (cleartext + wire bytes + annotations
        + source + timestamps) and any per-pane scratch, so a session
        can be reopened later and explored entirely offline.
        """
        snapshot = {
            "version": SESSION_VERSION,
            "mrz": {
                "doc_number": self.parent.doc_number.get(),
                "dob": self.parent.dob.get(),
                "expiry": self.parent.expiry.get(),
                "can": self.parent.can.get(),
            },
            "ef_raw": dict(self._ef_raw),
            "mf_ef_raw": dict(self._mf_ef_raw),
            "apdu_history": APDUHistory.get().to_list(),
        }

        scratch = {}
        for name in _SCRATCH_PANES:
            pane = getattr(self.root, f"{name}_pane", None)
            if pane is not None and hasattr(pane, "get_scratch"):
                try:
                    state = pane.get_scratch()
                except Exception:
                    logging.exception("Could not capture %s scratch", name)
                    continue
                if state:
                    scratch[name] = state
        if scratch:
            snapshot["scratch"] = scratch

        return snapshot

    def load_snapshot(self, data: dict) -> None:
        """Restore a saved research session (View, Traffic and scratch)."""
        self._validate_snapshot(data)

        mrz = data["mrz"]
        self.parent.doc_number.set(str(mrz.get("doc_number", "")))
        self.parent.dob.set(str(mrz.get("dob", "")))
        self.parent.expiry.set(str(mrz.get("expiry", "")))
        self.parent.can.set(str(mrz.get("can", "")))

        ef_dict = {}
        for ef_name, hex_str in data.get("ef_raw", {}).items():
            if not hex_str:
                continue
            try:
                raw = bytes.fromhex(hex_str)
                tag = dg_converter.toTAG(ef_name)
                cls_name = dg_converter.toClass(tag)
                ef_dict[ef_name] = _CLASS_MAP[cls_name](file=raw)
            except Exception as e:
                logging.warning(f"Could not parse {ef_name} from saved bytes: {e}")

        mf_ef_raw = {k: v for k, v in data.get("mf_ef_raw", {}).items() if v}

        self._reset_ef_tabs()
        self._ef_raw = {k: v for k, v in data.get("ef_raw", {}).items() if v}
        self._mf_ef_raw = dict(mf_ef_raw)

        for key in self.fields:
            self.fields[key].configure(text="None")

        # DG1 carries the printed-page fields shown at the top of the View tab.
        # A session may legitimately have none (e.g. a captured failed handshake
        # with no readable EFs), so its absence is not fatal — the Traffic and
        # scratch state below still restore.
        dg1 = ef_dict.get("DG1")
        if dg1 is not None:
            try:
                self.fields["type"].configure(text=dg1["5F1F"]["5F03"].replace("<", " ").strip())
                self.fields["country"].configure(text=dg1["5F1F"]["5F28"].replace("<", " ").strip())
                name = dg1["5F1F"]["5F5B"].split("<<")
                self.fields["surname"].configure(text=name[0].replace("<", " ").strip())
                self.fields["name"].configure(text=name[1].replace("<", " ").strip() if len(name) > 1 else "")
                self.fields["number"].configure(text=dg1["5F1F"]["5A"].replace("<", " ").strip())
                self.fields["nationality"].configure(text=dg1["5F1F"]["5F2C"].replace("<", " ").strip())
                self.fields["dob"].configure(text=dg1["5F1F"]["5F57"].replace("<", " ").strip())
                self.fields["sex"].configure(text=dg1["5F1F"]["5F35"].replace("<", " ").strip())
                self.fields["expiry"].configure(text=dg1["5F1F"]["59"].replace("<", " ").strip())
                self.fields["optional"].configure(text=dg1["5F1F"]["53"].replace("<", " ").strip())
            except (KeyError, AttributeError) as e:
                raise ValueError(f"Could not parse DG1 fields from saved data: {e}")

        dg2 = ef_dict.get("DG2")
        if dg2 is not None:
            try:
                self._photo_bytes = bytes(dg2["7F61"][0]["7F60"]["5F2E"])
                self._display_photo(self._photo_bytes)
            except Exception as e:
                logging.warning(f"Could not restore passport photo: {e}")

        for ef in _EF_NAMES:
            if ef in mf_ef_raw:
                self._set_ef_content(ef, mf_ef_raw[ef])
                continue
            ef_obj = ef_dict.get(ef)
            if ef_obj is not None:
                self._set_ef_content(ef, self._ef_to_str(ef, ef_obj))

        try:
            com = ef_dict.get("COM")
            advertised_tags = com.get("5C", []) if com else []
        except Exception:
            advertised_tags = []
        for tag_hex in advertised_tags:
            try:
                from pypassport.doc9303.converter import toDG
                ef_name = toDG(tag_hex)
            except Exception:
                continue
            if ef_name in self._ef_buttons and self._ef_contents.get(ef_name) is None:
                self._set_ef_content(
                    ef_name,
                    f"{ef_name} is listed in EF.COM but could not be read — "
                    f"the chip may require Active Authentication or another "
                    f"access condition before granting access.",
                    inaccessible=True,
                )

        if "DG1" in self._ef_contents and self._ef_contents["DG1"] is not None:
            self._select_ef("DG1")

        # Restore the APDU history and tell the Traffic tab to repaint. Imported
        # transactions are relabelled source="imported" so they're distinct from
        # anything captured live in this run, and they replay into Forge offline.
        APDUHistory.get().from_list(data.get("apdu_history", []), source="imported")
        traffic_pane = getattr(self.root, "traffic_pane", None)
        if traffic_pane is not None:
            traffic_pane.reload()

        # Restore per-pane scratch when both the saved
        # state and a pane able to consume it are present.
        for name, state in data.get("scratch", {}).items():
            pane = getattr(self.root, f"{name}_pane", None)
            if pane is not None and hasattr(pane, "load_scratch"):
                try:
                    pane.load_scratch(state)
                except Exception:
                    logging.exception("Could not restore %s scratch", name)

    def _display_photo(self, img_bytes: bytes) -> None:
        image = Image.open(io.BytesIO(img_bytes))
        max_width = 200
        width, height = image.size
        new_height = int(max_width * height / width)
        resized = image.resize((max_width, new_height), Image.Resampling.LANCZOS)
        tk_image = ImageTk.PhotoImage(resized)
        self.passport_photo.configure(image=tk_image, width=max_width, height=new_height, text="")
        self.passport_photo.image = tk_image

    @classmethod
    def _validate_snapshot(cls, data: dict) -> None:
        if not isinstance(data, dict):
            raise ValueError("Session must be a JSON object.")
        if data.get("version") != SESSION_VERSION:
            raise ValueError(f"Unsupported session version: {data.get('version')!r}")
        if not isinstance(data.get("mrz"), dict):
            raise ValueError("Session missing or invalid 'mrz' section.")
        if not isinstance(data.get("ef_raw"), dict):
            raise ValueError("Session missing or invalid 'ef_raw' section.")
        if not isinstance(data.get("apdu_history", []), list):
            raise ValueError("Session has an invalid 'apdu_history' section.")
