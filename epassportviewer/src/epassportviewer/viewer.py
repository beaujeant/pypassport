import logging
import io
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
from tkinter import messagebox
from pypassport.epassport import EPassport, EPassportException


# All EFs shown as tabs, in display order
_EF_NAMES = ["COM", "DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7",
             "DG8", "DG9", "DG10", "DG11", "DG12", "DG13", "DG14",
             "DG15", "DG16", "SOD"]


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

        # EF tab panel — fills remaining vertical space
        ef_notebook = ttk.Notebook(self.root.view_tab)
        ef_notebook.pack(fill="both", expand=True, padx=10, pady=(0, 5))
        self._ef_notebook = ef_notebook
        self._ef_texts = {}   # ef_name -> tk.Text widget
        self._ef_tabs = {}    # ef_name -> tab frame

        for ef in _EF_NAMES:
            frame = ttk.Frame(ef_notebook)
            ef_notebook.add(frame, text=ef)
            self._ef_tabs[ef] = frame

            text = tk.Text(frame, wrap="word", state="disabled", font=("Courier", 9), height=8)
            scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            text.pack(side="left", fill="both", expand=True)
            self._ef_texts[ef] = text

        # Select DG1 by default
        self._ef_notebook.select(self._ef_tabs["DG1"])

    def _reset_ef_tabs(self):
        for ef in _EF_NAMES:
            self._set_ef_content(ef, None)

    def _set_ef_content(self, ef, content):
        """Set tab content. None means unreadable (greyed out, empty)."""
        text_widget = self._ef_texts[ef]
        text_widget.configure(state="normal")
        text_widget.delete("1.0", "end")
        if content is not None:
            text_widget.insert("end", content)
            text_widget.configure(state="disabled", foreground="")
            self._ef_notebook.tab(self._ef_tabs[ef], state="normal")
        else:
            text_widget.configure(state="disabled", foreground="gray")
            self._ef_notebook.tab(self._ef_tabs[ef], state="disabled")

    def _ef_to_str(self, ef_name, data):
        if data is None:
            return None
        try:
            return str(data)
        except Exception:
            return repr(data)

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
            result = ep.open(can=can)
            logging.info(f"Access control: {result.mechanism}")
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

        try:
            dg2 = ep["DG2"]
            if dg2 is None:
                raise EPassportException("DG2 could not be read from the chip.")
            image_stream = io.BytesIO(dg2["7F61"][0]["7F60"]["5F2E"])
            image = Image.open(image_stream)

            max_width = 200
            width, height = image.size
            new_height = int(max_width * height / width)
            image = image.resize((max_width, new_height), Image.LANCZOS)

            tk_image = ImageTk.PhotoImage(image)
            self.passport_photo.configure(image=tk_image, width=max_width, height=new_height)
            self.passport_photo.image = tk_image
        except EPassportException as e:
            logging.error(f"Could not read DG2: {e}")
            messagebox.showerror("Passport photo unavailable", str(e))
        except Exception as e:
            logging.exception("Could not load passport photo from DG2")
            messagebox.showerror(
                "Passport photo unavailable",
                f"Could not load the passport photo: {e}",
            )

        # Populate EF tabs
        self._reset_ef_tabs()
        for ef in _EF_NAMES:
            # DG1 is guaranteed readable — use the already-parsed local variable
            # so a failed re-read attempt never clears the tab.
            if ef == "DG1":
                self._set_ef_content("DG1", self._ef_to_str("DG1", dg1))
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
            try:
                content = self._ef_to_str(ef, data)
            except Exception as e:
                logging.warning(f"Could not stringify {ef}: {e}")
                content = f"(Could not display {ef}: {e})"
            self._set_ef_content(ef, content)

        self._ef_notebook.select(self._ef_tabs["DG1"])

    def update_field(self, item, value):
        self.fields[item].config(text=value)
