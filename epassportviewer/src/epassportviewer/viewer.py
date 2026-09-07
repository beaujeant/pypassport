from __future__ import annotations

import io
import logging
import queue
import threading
import tkinter as tk
from collections.abc import Callable, Mapping
from functools import partial
from tkinter import filedialog, messagebox, ttk
from typing import Any

from PIL import Image, ImageTk

from pypassport.apdu_history import APDUHistory
from pypassport.doc9303 import converter as dg_converter
from pypassport.doc9303.data_group import _CLASS_MAP, BiometricTemplates
from pypassport.epassport import EPassportException
from pypassport.iso7816 import APDUCommand

from . import theme

# Row 1: file-system / meta EFs in logical access order
_ROW1 = ["ATR/INFO", "DIR", "CardAccess", "CardSecurity", "COM", "SOD"]
# Row 2: DG1–DG8
_ROW2 = ["DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7", "DG8"]
# Row 3: DG9–DG16
_ROW3 = ["DG9", "DG10", "DG11", "DG12", "DG13", "DG14", "DG15", "DG16"]
_EF_NAMES = _ROW1 + _ROW2 + _ROW3
_INTEGRITY_OK = "ok"
_INTEGRITY_MISMATCH = "mismatch"
_INTEGRITY_UNKNOWN = "unknown"
_SIGNATURE_VERIFYING = "verifying"
_SIGNATURE_VALID = "valid"
_SIGNATURE_INVALID = "invalid"
_AA_VERIFYING = "verifying"
_AA_VALID = "valid"
_AA_INVALID = "invalid"
_AA_UNAVAILABLE = "unavailable"
_AA_ERROR = "error"


def _dg_sort_key(name: str) -> tuple[int, str]:
    digits = "".join(char for char in name if char.isdigit())
    return (int(digits) if digits else 999, name)


def _sod_listed_dgs(sod: Any) -> list[str]:
    """Return the DG names declared in EF.SOD, in numerical order."""

    if not isinstance(sod, Mapping):
        return []
    hashes = sod.get("dg_hashes", {})
    if not isinstance(hashes, Mapping):
        return []

    names: set[str] = set()
    for key in hashes:
        if isinstance(key, str) and key.upper().startswith("DG"):
            name = key.upper()
            if not name[2:].isdigit():
                continue
        else:
            try:
                number = int(key)
            except (TypeError, ValueError):
                continue
            if number < 1:
                continue
            name = f"DG{number}"
        names.add(name)
    return sorted(names, key=_dg_sort_key)


def _sod_integrity_states(
    sod: Any,
    integrity: Mapping[str, bool | None] | None,
) -> list[tuple[str, str]]:
    """Map every SOD-listed DG to a View badge state."""

    results = integrity if isinstance(integrity, Mapping) else {}
    states = []
    for name in _sod_listed_dgs(sod):
        outcome = results.get(name)
        if outcome is True:
            state = _INTEGRITY_OK
        elif outcome is False:
            state = _INTEGRITY_MISMATCH
        else:
            state = _INTEGRITY_UNKNOWN
        states.append((name, state))
    return states


class ViewerPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._auth_busy = False

        # Inner menu frame
        reader_info = ttk.Frame(self.root.view_tab)
        reader_info.pack(fill="x", pady=10, padx=10)

        # "Read" button — the primary action on this tab.
        self.root.read_button = ttk.Button(
            reader_info,
            text="Read",
            command=self.read_passport,
            style="Accent.TButton",
            state="disabled",
        )
        self.root.read_button.pack(side="left", padx=5)

        # Top section: photo + passport info side by side
        top_frame = ttk.Frame(self.root.view_tab)
        top_frame.pack(fill="x", padx=10, anchor="n")

        # Left side for image
        image_frame = ttk.Frame(top_frame, width=200, height=300)
        image_frame.pack(side="left", padx=10, anchor="n")

        # Placeholder for the passport photo
        self.passport_photo = tk.Label(
            image_frame,
            text="Passport Photo\n(200 × 300)",
            width=25,
            height=15,
            background=theme.SURFACE,
            foreground=theme.TEXT_MUTED,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=theme.BORDER,
            highlightcolor=theme.BORDER,
        )
        self.passport_photo.pack(padx=5, pady=5)
        self._photo_image: ImageTk.PhotoImage | None = None

        # Right side for textual information
        info_frame = ttk.Frame(top_frame)
        info_frame.pack(side="left", pady=5, anchor="n")

        # Define labels for each field in 3 columns
        self.fields = {}
        default_val = "None"

        # Two evenly-spaced columns of caption/value pairs.
        info_frame.columnconfigure(0, minsize=280, weight=1)
        info_frame.columnconfigure(1, minsize=280, weight=1)

        ttk.Label(info_frame, text="Type", style="Caption.TLabel").grid(row=0, column=0, sticky="w", padx=5)
        self.fields["type"] = ttk.Label(info_frame, text=default_val)
        self.fields["type"].grid(row=1, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Surname", style="Caption.TLabel").grid(row=2, column=0, sticky="w", padx=5)
        self.fields["surname"] = ttk.Label(info_frame, text=default_val)
        self.fields["surname"].grid(row=3, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Name", style="Caption.TLabel").grid(row=4, column=0, sticky="w", padx=5)
        self.fields["name"] = ttk.Label(info_frame, text=default_val)
        self.fields["name"].grid(row=5, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Nationality", style="Caption.TLabel").grid(row=6, column=0, sticky="w", padx=5)
        self.fields["nationality"] = ttk.Label(info_frame, text=default_val)
        self.fields["nationality"].grid(row=7, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Date of Birth", style="Caption.TLabel").grid(row=8, column=0, sticky="w", padx=5)
        self.fields["dob"] = ttk.Label(info_frame, text=default_val)
        self.fields["dob"].grid(row=9, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Signature", style="Caption.TLabel").grid(row=10, column=0, sticky="w", padx=5)
        self.fields["signature"] = ttk.Label(info_frame, text=default_val)
        self.fields["signature"].grid(row=11, column=0, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Passport Number", style="Caption.TLabel").grid(row=0, column=1, sticky="w", padx=5)
        self.fields["number"] = ttk.Label(info_frame, text=default_val)
        self.fields["number"].grid(row=1, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Issuing Country", style="Caption.TLabel").grid(row=2, column=1, sticky="w", padx=5)
        self.fields["country"] = ttk.Label(info_frame, text=default_val)
        self.fields["country"].grid(row=3, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Sex", style="Caption.TLabel").grid(row=4, column=1, sticky="w", padx=5)
        self.fields["sex"] = ttk.Label(info_frame, text=default_val)
        self.fields["sex"].grid(row=5, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Date of Expiry", style="Caption.TLabel").grid(row=6, column=1, sticky="w", padx=5)
        self.fields["expiry"] = ttk.Label(info_frame, text=default_val)
        self.fields["expiry"].grid(row=7, column=1, sticky="w", pady=(4, 10), padx=5)

        ttk.Label(info_frame, text="Optional Data", style="Caption.TLabel").grid(row=8, column=1, sticky="w", padx=5)
        self.fields["optional"] = ttk.Label(info_frame, text=default_val)
        self.fields["optional"].grid(row=9, column=1, sticky="w", pady=(4, 10), padx=5)

        # EF panel: two-row custom tab bar + shared content area
        ef_panel = ttk.Frame(self.root.view_tab)
        ef_panel.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        # Two-row button bar — each row is a separate frame so buttons in
        # each row are sized equally within that row while both rows share
        # the same total width.
        tab_bar = ttk.Frame(ef_panel)
        tab_bar.pack(fill="x")

        self._ef_buttons = {}
        self._ef_contents = {}  # ef_name -> {"readable": str, "raw": str} or None
        self._ef_inaccessible = set()  # EFs advertised in EF.COM but unreadable
        self._selected_ef = None
        self._photo_bytes = None  # raw image bytes from DG2, kept for Save
        self._ef_raw = {}
        self._mf_ef_raw = {}

        fam = theme.FONT_SMALL[0]
        sz = theme.FONT_SMALL[1]
        style = ttk.Style()
        style.configure(
            "EFTab.TButton",
            background=theme.SURFACE_ALT,
            foreground=theme.TEXT,
            bordercolor=theme.BORDER,
            font=(fam, sz),
            padding=(8, 5),
        )
        style.map(
            "EFTab.TButton",
            background=[("pressed", theme.BORDER_STRONG), ("active", theme.BORDER)],
            foreground=[("disabled", theme.TEXT_DISABLED)],
        )
        style.configure(
            "EFTabActive.TButton",
            background=theme.ACCENT,
            foreground=theme.TEXT_ON_ACCENT,
            bordercolor=theme.ACCENT,
            lightcolor=theme.ACCENT,
            darkcolor=theme.ACCENT_ACTIVE,
            font=(fam, sz),
            padding=(8, 5),
        )
        style.map(
            "EFTabActive.TButton",
            background=[("pressed", theme.ACCENT_ACTIVE), ("active", theme.ACCENT_HOVER)],
            foreground=[("pressed", theme.TEXT_ON_ACCENT), ("active", theme.TEXT_ON_ACCENT)],
            bordercolor=[("pressed", theme.ACCENT_ACTIVE), ("active", theme.ACCENT_HOVER)],
        )
        style.configure(
            "EFTabInaccessible.TButton",
            background=theme.SURFACE_ALT,
            foreground=theme.TEXT_MUTED,
            bordercolor=theme.BORDER,
            font=(fam, sz, "italic"),
            padding=(8, 5),
        )
        style.map(
            "EFTabInaccessible.TButton",
            background=[("pressed", theme.BORDER_STRONG), ("active", theme.BORDER)],
            foreground=[("disabled", theme.TEXT_DISABLED)],
        )
        style.configure(
            "EFTabInaccessibleActive.TButton",
            background=theme.ACCENT,
            foreground=theme.TEXT_ON_ACCENT,
            bordercolor=theme.ACCENT,
            lightcolor=theme.ACCENT,
            darkcolor=theme.ACCENT_ACTIVE,
            font=(fam, sz, "italic"),
            padding=(8, 5),
        )
        style.map(
            "EFTabInaccessibleActive.TButton",
            background=[("pressed", theme.ACCENT_ACTIVE), ("active", theme.ACCENT_HOVER)],
            foreground=[("pressed", theme.TEXT_ON_ACCENT), ("active", theme.TEXT_ON_ACCENT)],
            bordercolor=[("pressed", theme.ACCENT_ACTIVE), ("active", theme.ACCENT_HOVER)],
        )
        for style_name, background in (
            ("DGIntegrityOk.TLabel", theme.OK_BG),
            ("DGIntegrityMismatch.TLabel", theme.ERR_BG),
            ("DGIntegrityUnknown.TLabel", theme.WARN_BG),
        ):
            style.configure(
                style_name,
                background=background,
                foreground=theme.TEXT,
                font=(fam, sz, "bold"),
                padding=(6, 3),
            )

        for row_index, row_efs in enumerate((_ROW1, _ROW2, _ROW3)):
            row_frame = ttk.Frame(tab_bar)
            row_frame.pack(fill="x", side="top")
            for ef in row_efs:
                btn = ttk.Button(
                    row_frame,
                    text=ef,
                    style="EFTab.TButton",
                    state="disabled",
                    command=partial(self._select_ef, ef),
                )
                btn.pack(side="left", padx=1, pady=1)
                self._ef_buttons[ef] = btn

        # Shared content area
        content_frame = ttk.Frame(ef_panel)
        content_frame.pack(fill="both", expand=True, pady=(6, 0))

        self._ef_view_notebook = ttk.Notebook(content_frame)
        self._ef_view_notebook.pack(fill="both", expand=True)
        self._ef_texts = {
            "readable": self._build_ef_text_tab(self._ef_view_notebook, "Readable", wrap="word"),
            "raw": self._build_ef_text_tab(self._ef_view_notebook, "Raw", wrap="none"),
        }
        self._build_integrity_strip(ef_panel)
        self.root.after(100, self._drain)

    @staticmethod
    def _build_ef_text_tab(notebook, label, *, wrap):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=label)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        text = tk.Text(frame, wrap=wrap, state="disabled", height=10)
        theme.style_text(text)
        vertical = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vertical.set)
        text.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        if wrap == "none":
            horizontal = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
            text.configure(xscrollcommand=horizontal.set)
            horizontal.grid(row=1, column=0, sticky="ew")
        return text

    def _build_integrity_strip(self, parent) -> None:
        strip = ttk.Frame(parent)
        strip.pack(fill="x", pady=(6, 0))

        ttk.Label(strip, text="SOD", style="Caption.TLabel").pack(side="left", padx=(0, 6))
        self._integrity_badges = ttk.Frame(strip)
        self._integrity_badges.pack(side="left", fill="x", expand=True)
        self._dg_badges = ttk.Frame(self._integrity_badges)
        self._dg_badges.pack(side="left")
        self._signature_badge = ttk.Label(self._integrity_badges)
        self._active_auth_badge = ttk.Label(self._integrity_badges)

        actions = ttk.Frame(strip)
        actions.pack(side="right")
        self._verify_signature_button = ttk.Button(
            actions,
            text="Verify Signature",
            command=self._verify_signature,
            state="disabled",
        )
        self._verify_signature_button.pack(side="right")
        self._active_auth_button = ttk.Button(
            actions,
            text="Active Authentication",
            command=self._verify_active_authentication,
            state="disabled",
        )
        self._active_auth_button.pack(side="right", padx=(0, 4))
        self._reset_integrity_strip()

    def _select_ef(self, ef):
        self._selected_ef = ef
        content = self._ef_contents.get(ef)
        for mode, text in self._ef_texts.items():
            text.configure(state="normal")
            text.delete("1.0", "end")
            if content is not None:
                text.insert("end", content.get(mode, ""))
            text.configure(state="disabled")
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
        for text in self._ef_texts.values():
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.configure(state="disabled")
        self._reset_photo()
        self._reset_integrity_strip()

    def _reset_photo(self):
        """Restore the photo box to its empty placeholder."""
        self.passport_photo.configure(
            image="",
            text="Passport Photo\n(200 × 300)",
            width=25,
            height=15,
        )
        self._photo_image = None

    def _reset_integrity_strip(self) -> None:
        self._auth_busy = False
        self._render_integrity_badges([])
        self._set_signature_badge(None)
        self._set_active_auth_badge(None)
        self._update_auth_buttons()

    def _render_integrity_badges(self, states: list[tuple[str, str]]) -> None:
        for child in self._dg_badges.winfo_children():
            child.destroy()
        if not states:
            ttk.Label(self._dg_badges, text="No SOD integrity data", style="Muted.TLabel").pack(side="left")
            return

        styles = {
            _INTEGRITY_OK: "DGIntegrityOk.TLabel",
            _INTEGRITY_MISMATCH: "DGIntegrityMismatch.TLabel",
            _INTEGRITY_UNKNOWN: "DGIntegrityUnknown.TLabel",
        }
        for name, state in states:
            ttk.Label(self._dg_badges, text=name, style=styles[state]).pack(side="left", padx=(0, 4))

    def _set_signature_badge(self, state: str | None) -> None:
        if state is None:
            self._signature_badge.pack_forget()
            return
        styles = {
            _SIGNATURE_VERIFYING: ("Signature: verifying...", "DGIntegrityUnknown.TLabel"),
            _SIGNATURE_VALID: ("Signature: valid", "DGIntegrityOk.TLabel"),
            _SIGNATURE_INVALID: ("Signature: invalid", "DGIntegrityMismatch.TLabel"),
        }
        text, style = styles[state]
        self._signature_badge.configure(text=text, style=style)
        if not self._signature_badge.winfo_manager():
            self._signature_badge.pack(side="left", padx=(0, 4))

    def _set_active_auth_badge(self, state: str | None) -> None:
        if state is None:
            self._active_auth_badge.pack_forget()
            return
        styles = {
            _AA_VERIFYING: ("AA: verifying...", "DGIntegrityUnknown.TLabel"),
            _AA_VALID: ("AA: valid", "DGIntegrityOk.TLabel"),
            _AA_INVALID: ("AA: invalid", "DGIntegrityMismatch.TLabel"),
            _AA_UNAVAILABLE: ("AA: unavailable", "DGIntegrityUnknown.TLabel"),
            _AA_ERROR: ("AA: error", "DGIntegrityUnknown.TLabel"),
        }
        text, style = styles[state]
        self._active_auth_badge.configure(text=text, style=style)
        if not self._active_auth_badge.winfo_manager():
            self._active_auth_badge.pack(side="left", padx=(0, 4))

    def _set_ef_content(self, ef, content, inaccessible=False):
        if isinstance(content, str):
            content = {"readable": content, "raw": content}
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

    def _ef_to_content(self, ef_name, data):
        if data is None:
            return None
        try:
            if hasattr(data, "to_json"):
                raw = data.to_json()
                try:
                    readable = data.to_readable_json() if hasattr(data, "to_readable_json") else raw
                except Exception as e:
                    logging.warning(f"Could not render readable {ef_name}: {e}")
                    readable = raw
                return {"readable": readable, "raw": raw}
            rendered = str(data)
            return {"readable": rendered, "raw": rendered}
        except Exception:
            rendered = repr(data)
            return {"readable": rendered, "raw": rendered}

    @staticmethod
    def _cached_ep_file(ep, ef_name):
        if ef_name not in ep:
            return None
        return dict.__getitem__(ep, ef_name)

    def _update_integrity_strip(self, ep) -> dict[str, bool | None]:
        dg15 = self._cached_ep_file(ep, "DG15")
        self._set_active_auth_badge(None if dg15 is not None else _AA_UNAVAILABLE)
        self._update_auth_buttons(ep)

        sod = self._cached_ep_file(ep, "SOD")
        if sod is None:
            self._render_integrity_badges([])
            return {}

        dgs = []
        for name in _sod_listed_dgs(sod):
            dg = self._cached_ep_file(ep, name)
            if dg is not None:
                dgs.append(dg)

        integrity: dict[str, bool | None] = {}
        if dgs:
            try:
                integrity = dict(ep.do_verify_dg_integrity(dgs=dgs) or {})
            except Exception as exc:
                logging.warning("Could not verify cached DG integrity: %s", exc)
        self._render_integrity_badges(_sod_integrity_states(sod, integrity))
        return integrity

    def _update_auth_buttons(self, ep=None) -> None:
        current_ep = self.parent.ep if ep is None else ep
        has_sod = current_ep is not None and self._cached_ep_file(current_ep, "SOD") is not None
        has_dg15 = current_ep is not None and self._cached_ep_file(current_ep, "DG15") is not None
        enabled = not self._auth_busy
        self._verify_signature_button.configure(state="normal" if enabled and has_sod else "disabled")
        self._active_auth_button.configure(state="normal" if enabled and has_dg15 else "disabled")

    def _set_auth_busy(self, busy: bool, ep=None) -> None:
        self._auth_busy = busy
        self._update_auth_buttons(ep)

    def _ensure_csca_directory(self) -> str | None:
        csca_dir = str(self.parent.settings.csca_dir)
        if csca_dir:
            return csca_dir
        path = filedialog.askdirectory(
            title="Select CSCA certificate directory",
            initialdir=None,
            parent=self.root,
        )
        if not path:
            return None
        path = str(path)
        self.parent.settings.csca_dir = path
        return path

    def _verify_signature(self) -> None:
        ep = self.parent.ep
        if ep is None or self._cached_ep_file(ep, "SOD") is None:
            return
        csca_dir = self._ensure_csca_directory()
        if csca_dir is None:
            return

        self._set_signature_badge(_SIGNATURE_VERIFYING)
        self._set_auth_busy(True, ep)

        def worker() -> None:
            error = None
            try:
                with self.parent.card_operation("GUI: passive authentication"):
                    ep.csca_directory = csca_dir
                    ep.do_verify_sod_certificate()
                verified = True
            except Exception as exc:
                logging.warning("SOD signature verification failed: %s", exc)
                error = str(exc)
                verified = False
            self._post(partial(self._finish_signature_verification, ep, verified, error))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_signature_verification(self, ep, verified: bool, error: str | None) -> None:
        if self.parent.ep is not ep:
            return
        self._set_auth_busy(False, ep)
        self._set_signature_badge(_SIGNATURE_VALID if verified else _SIGNATURE_INVALID)
        self._refresh_security_from_cache(
            checks={
                "sod_signature_verified": verified,
                "sod_signature_error": error or "",
            }
        )
        if error:
            messagebox.showerror("Signature verification failed", error, parent=self.root)

    def _verify_active_authentication(self) -> None:
        ep = self.parent.ep
        if ep is None:
            return
        dg15 = self._cached_ep_file(ep, "DG15")
        if dg15 is None:
            self._set_active_auth_badge(_AA_UNAVAILABLE)
            return

        self._set_active_auth_badge(_AA_VERIFYING)
        self._set_auth_busy(True, ep)

        def worker() -> None:
            error = None
            try:
                with self.parent.card_operation("GUI: active authentication"):
                    ep.iso7816.source = "read"
                    verified = bool(ep.do_active_authentication(dg15))
            except Exception as exc:
                logging.warning("Active Authentication failed: %s", exc)
                error = str(exc)
                verified = False
            self._post(partial(self._finish_active_authentication, ep, verified, error))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_active_authentication(self, ep, verified: bool, error: str | None) -> None:
        if self.parent.ep is not ep:
            return
        self._set_auth_busy(False, ep)
        self._refresh_security_from_cache(
            checks={
                "active_authentication": verified,
                "active_authentication_error": error or "",
            }
        )
        if error:
            self._set_active_auth_badge(_AA_ERROR)
            messagebox.showerror("Active Authentication failed", error, parent=self.root)
            return
        self._set_active_auth_badge(_AA_VALID if verified else _AA_INVALID)

    def _post(self, fn: Callable[[], None]) -> None:
        self._queue.put(fn)

    def _drain(self) -> None:
        try:
            while True:
                fn = self._queue.get_nowait()
                try:
                    fn()
                except Exception:
                    logging.exception("View: UI update failed")
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

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
            iso7816.select_elementary_file(fid)
        except Exception:
            return None
        for size in (0xDF, 0x7F, 0x3F, 0x1F, 0x0F, 0x04):
            try:
                data = iso7816.read_binary(0, size)
                return data.hex().upper()
            except Exception:
                continue
        return None

    @staticmethod
    def _collect_security_live_details(ep) -> dict[str, Any]:
        details: dict[str, Any] = {"atr": None, "uid": None, "acquisition_errors": {}}
        try:
            details["atr"] = ep.iso7816.get_atr()
        except Exception as exc:
            details["acquisition_errors"]["ATR"] = str(exc)
        try:
            details["uid"] = ep.iso7816.get_uid()
        except Exception as exc:
            details["acquisition_errors"]["UID"] = str(exc)
        return details

    def read_passport(self):
        try:
            with self.parent.card_operation("GUI: read passport"):
                return self._read_passport()
        except Exception as exc:
            if type(exc).__name__ != "CardBusy":
                raise
            messagebox.showwarning("Card busy", str(exc), parent=self.root)

    def _read_passport(self):
        doc_number = self.parent.doc_number.get().strip()
        dob = self.parent.dob.get().strip()
        expiry = self.parent.expiry.get().strip()
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
            # Build a fresh shared session: an explicit Read always re-fetches
            # from the chip. get_passport publishes this session (and its
            # iso7816, carrying the BAC/PACE Secure Messaging context and its
            # live SSC counter) as the shared one, so the Security, Forge and
            # Intercept tabs reuse the same channel and cached data groups
            # instead of re-running access control and re-reading the chip.
            ep = self.parent.get_passport(
                (doc_number, dob, expiry) if mrz_supplied else None,
                can,
                force_new=True,
            )
            security_live_details = self._collect_security_live_details(ep)
            # Read MF-level files now, before ep.open() selects the eMRTD AID.
            # Attempting to select these FIDs (2F01, 2F00) after AID selection
            # can deselect the eMRTD application on many cards.
            mf_ef_raw = {
                "ATR/INFO": self._read_mf_ef(ep.iso7816, "2F01"),
                "DIR": self._read_mf_ef(ep.iso7816, "2F00"),
            }
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

        security_errors = security_live_details["acquisition_errors"]
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
            self._apply_dg1_values(self._dg1_values(dg1))
        except ValueError as e:
            logging.exception("Could not parse DG1 fields")
            messagebox.showwarning(
                "DG1 layout warning",
                f"DG1 was read but does not match the expected MRZ layout: {e}\n\n"
                "The raw and partially parsed DG1 content is still available in the DG1 tab.",
            )

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
            faces = dg2.get_biometric_data()
            if not faces:
                raise EPassportException("DG2 did not contain a readable face image.")
            self._photo_bytes = faces[0]
            self._display_photo(self._photo_bytes)
        except EPassportException as e:
            logging.error(f"Could not read DG2: {e}")
            security_errors["DG2"] = str(e)
            messagebox.showerror("Passport photo unavailable", str(e))
        except Exception as e:
            logging.exception("Could not load passport photo from DG2")
            security_errors["DG2"] = str(e)
            messagebox.showerror(
                "Passport photo unavailable",
                f"Could not load the passport photo: {e}",
            )
        for ef in _EF_NAMES:
            # DG1 is guaranteed readable — use the already-parsed local variable
            # so a failed re-read attempt never clears the tab.
            if ef == "DG1":
                self._set_ef_content("DG1", self._ef_to_content("DG1", dg1))
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
                security_errors[ef] = str(e)
                self._set_ef_content(ef, None)
                continue
            if data is None:
                logging.warning(f"{ef} returned None (chip read or parsing failed)")
                security_errors.setdefault(ef, "File returned no parsed data.")
                self._set_ef_content(ef, None)
                continue
            if hasattr(data, "file"):
                self._ef_raw[ef] = data.file.hex()
            try:
                content = self._ef_to_content(ef, data)
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
                from pypassport.doc9303.converter import to_dg

                ef_name = to_dg(tag_hex)
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
        integrity = self._update_integrity_strip(ep)
        self._refresh_security_from_cache(integrity=integrity, live_details=security_live_details)

    def refresh_from_passport(self) -> bool:
        """Merge files already cached by an MCP operation into the View pane.

        This intentionally performs no card reads. The shared passport object
        is the authoritative cache; live APDUs remain visible through the
        normal ISO7816/APDUHistory path while this method updates the GUI.
        """

        ep = self.parent.ep
        if ep is None:
            self._update_auth_buttons(None)
            return False

        changed = False
        dg1 = self._cached_ep_file(ep, "DG1")
        if dg1 is not None:
            try:
                self._apply_dg1_values(self._dg1_values(dg1))
            except ValueError as exc:
                logging.warning("Could not render MCP-cached DG1: %s", exc)

        dg2 = self._cached_ep_file(ep, "DG2")
        if isinstance(dg2, BiometricTemplates):
            try:
                faces = dg2.get_biometric_data()
                if faces:
                    self._photo_bytes = faces[0]
                    self._display_photo(self._photo_bytes)
            except Exception as exc:
                logging.warning("Could not render MCP-cached DG2: %s", exc)

        for ef in _EF_NAMES:
            data = self._cached_ep_file(ep, ef)
            if data is None:
                continue
            changed = True
            if hasattr(data, "file"):
                self._ef_raw[ef] = data.file.hex()
            try:
                content = self._ef_to_content(ef, data)
            except Exception as exc:
                content = f"(Could not display {ef}: {exc})"
            self._set_ef_content(ef, content)

        integrity = self._update_integrity_strip(ep)
        self._refresh_security_from_cache(integrity=integrity)
        if changed and self._ef_contents.get("DG1") is not None:
            self._select_ef("DG1")
        return changed

    def update_field(self, item, value):
        self.fields[item].config(text=value)

    @staticmethod
    def _dg1_values(dg1) -> dict[str, str]:
        try:
            name = dg1["5F1F"]["5F5B"].split("<<")
            return {
                "type": dg1["5F1F"]["5F03"].replace("<", " ").strip(),
                "country": dg1["5F1F"]["5F28"].replace("<", " ").strip(),
                "surname": name[0].replace("<", " ").strip(),
                "name": name[1].replace("<", " ").strip() if len(name) > 1 else "",
                "number": dg1["5F1F"]["5A"].replace("<", " ").strip(),
                "nationality": dg1["5F1F"]["5F2C"].replace("<", " ").strip(),
                "dob": dg1["5F1F"]["5F57"].replace("<", " ").strip(),
                "sex": dg1["5F1F"]["5F35"].replace("<", " ").strip(),
                "expiry": dg1["5F1F"]["59"].replace("<", " ").strip(),
                "optional": dg1["5F1F"]["53"].replace("<", " ").strip(),
            }
        except (KeyError, AttributeError) as exc:
            raise ValueError(f"Could not parse DG1 fields: {exc}") from exc

    def _apply_dg1_values(self, values: Mapping[str, str]) -> None:
        for key, value in values.items():
            self.fields[key].configure(text=value)

    # ------------------------------------------------------------------ #
    # Session snapshot: save / restore a whole research session            #
    # (MRZ/CAN, raw EFs, and the full APDU history) without touching a chip #
    # ------------------------------------------------------------------ #

    def get_snapshot(self) -> dict:
        """Return a JSON-serialisable dict capturing the whole session.

        Covers the credentials entered, every raw EF read on the View tab, and
        the complete APDU history (cleartext + wire bytes + annotations) plus
        analyst-facing Security capture context so a session can be reopened —
        and its traffic replayed into Forge — offline.
        """
        security_pane = getattr(self.parent, "security_pane", None)
        capture_context = security_pane.get_snapshot_metadata() if security_pane is not None else {}
        return {
            "version": 3,
            "mrz": {
                "doc_number": self.parent.doc_number.get(),
                "dob": self.parent.dob.get(),
                "expiry": self.parent.expiry.get(),
                "can": self.parent.can.get(),
            },
            "ef_raw": dict(self._ef_raw),
            "mf_ef_raw": dict(self._mf_ef_raw),
            "apdu_history": APDUHistory.get().to_list(),
            "capture_context": capture_context,
        }

    def load_snapshot(self, data: dict) -> None:
        """Restore a whole session: credentials, EF view, and APDU history.

        The Traffic tab reads from the same global history, so the caller is
        responsible for refreshing it once this returns.
        """
        self._validate_snapshot(data)
        prepared_view = self._prepare_snapshot_view(data)

        # An imported session is an offline capture. Do not leave the previous
        # live passport or Secure Messaging channel attached while the View and
        # Security panes are showing different evidence.
        self.parent.ep = None
        self.parent._ep_signature = None
        self.parent.iso7816 = None

        mrz = data["mrz"]
        self.parent.doc_number.set(str(mrz.get("doc_number", "")))
        self.parent.dob.set(str(mrz.get("dob", "")))
        self.parent.expiry.set(str(mrz.get("expiry", "")))
        self.parent.can.set(str(mrz.get("can", "")))

        # The parse step above validated DG1 before the live session was
        # detached. Applying the prepared view now cannot silently turn a bad
        # import into an empty session.
        self._restore_view(data, prepared=prepared_view)

        # Restore the APDU history. Records are tagged source="imported" so
        # restored traffic is distinct from anything captured live this run.
        APDUHistory.get().from_list(data.get("apdu_history", []), source="imported")

        security_pane = getattr(self.parent, "security_pane", None)
        if security_pane is not None:
            security_pane.load_snapshot_metadata(data.get("capture_context"))

    def _refresh_security_from_cache(
        self,
        *,
        checks: Mapping[str, Any] | None = None,
        integrity: Mapping[str, bool | None] | None = None,
        live_details: Mapping[str, Any] | None = None,
    ) -> None:
        security_pane = getattr(self.parent, "security_pane", None)
        if security_pane is not None:
            security_pane.refresh_cached(checks=checks, integrity=integrity, live_details=live_details)

    def _prepare_snapshot_view(self, data: dict) -> tuple[dict[str, Any], dict[str, str], dict[str, str] | None]:
        """Parse saved EF bytes before mutating widgets or live-session state."""

        ef_dict: dict[str, Any] = {}
        for ef_name, hex_str in data.get("ef_raw", {}).items():
            if not isinstance(ef_name, str) or not isinstance(hex_str, str) or not hex_str:
                continue
            try:
                raw = bytes.fromhex(hex_str)
                tag = dg_converter.to_tag(ef_name)
                cls_name = dg_converter.to_class(tag)
                ef_dict[ef_name] = _CLASS_MAP[cls_name](file=raw)
            except Exception as exc:
                if ef_name == "DG1":
                    raise ValueError(f"Could not parse DG1 from saved bytes: {exc}") from exc
                logging.warning(f"Could not parse {ef_name} from saved bytes: {exc}")

        mf_ef_raw = {
            key: value
            for key, value in data.get("mf_ef_raw", {}).items()
            if isinstance(key, str) and isinstance(value, str) and value
        }
        dg1 = ef_dict.get("DG1")
        dg1_values = self._dg1_values(dg1) if dg1 is not None else None
        return ef_dict, mf_ef_raw, dg1_values

    def _restore_view(
        self,
        data: dict,
        *,
        prepared: tuple[dict[str, Any], dict[str, str], dict[str, str] | None] | None = None,
    ) -> None:
        """Repopulate the View tab (fields, photo, EF tabs) from raw EF bytes.

        A session with no DG1 — e.g. one that only captured Forge traffic —
        leaves the identity fields blank but still restores any other raw EFs.
        """
        ef_dict, mf_ef_raw, dg1_values = prepared or self._prepare_snapshot_view(data)

        self._reset_ef_tabs()
        for key in self.fields:
            self.fields[key].configure(text="None")

        self._ef_raw = {
            key: value
            for key, value in data.get("ef_raw", {}).items()
            if isinstance(key, str) and isinstance(value, str) and value
        }
        self._mf_ef_raw = dict(mf_ef_raw)

        if dg1_values is not None:
            self._apply_dg1_values(dg1_values)

        dg2 = ef_dict.get("DG2")
        if isinstance(dg2, BiometricTemplates):
            try:
                faces = dg2.get_biometric_data()
                if not faces:
                    raise ValueError("DG2 did not contain a readable face image")
                self._photo_bytes = faces[0]
                self._display_photo(self._photo_bytes)
            except Exception as e:
                logging.warning(f"Could not restore passport photo: {e}")

        for ef in _EF_NAMES:
            if ef in mf_ef_raw:
                self._set_ef_content(ef, mf_ef_raw[ef])
                continue
            ef_obj = ef_dict.get(ef)
            if ef_obj is not None:
                self._set_ef_content(ef, self._ef_to_content(ef, ef_obj))

        try:
            com = ef_dict.get("COM")
            advertised_tags = com.get("5C", []) if com else []
        except Exception:
            advertised_tags = []
        for tag_hex in advertised_tags:
            try:
                from pypassport.doc9303.converter import to_dg

                ef_name = to_dg(tag_hex)
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

        self._restore_integrity_strip(ef_dict, data.get("capture_context"))
        if self._ef_contents.get("DG1") is not None:
            self._select_ef("DG1")

    def _restore_integrity_strip(self, ef_dict: Mapping[str, Any], capture_context: Any) -> None:
        context = capture_context if isinstance(capture_context, Mapping) else {}
        integrity = context.get("integrity")
        integrity = integrity if isinstance(integrity, Mapping) else {}
        self._render_integrity_badges(_sod_integrity_states(ef_dict.get("SOD"), integrity))

        checks = context.get("checks")
        checks = checks if isinstance(checks, Mapping) else {}
        if checks.get("sod_signature_verified") is True:
            self._set_signature_badge(_SIGNATURE_VALID)
        elif checks.get("sod_signature_verified") is False:
            self._set_signature_badge(_SIGNATURE_INVALID)

        if checks.get("active_authentication_error"):
            self._set_active_auth_badge(_AA_ERROR)
        elif checks.get("active_authentication") is True:
            self._set_active_auth_badge(_AA_VALID)
        elif checks.get("active_authentication") is False:
            self._set_active_auth_badge(_AA_INVALID)
        elif ef_dict and ef_dict.get("DG15") is None:
            self._set_active_auth_badge(_AA_UNAVAILABLE)

    def _display_photo(self, img_bytes: bytes) -> None:
        image = Image.open(io.BytesIO(img_bytes))
        max_width = 200
        width, height = image.size
        new_height = int(max_width * height / width)
        resized = image.resize((max_width, new_height), Image.Resampling.LANCZOS)
        tk_image = ImageTk.PhotoImage(resized)
        self.passport_photo.configure(image=tk_image, width=max_width, height=new_height, text="")
        self._photo_image = tk_image

    @classmethod
    def _validate_snapshot(cls, data: dict) -> None:
        if not isinstance(data, dict):
            raise ValueError("Session file must be a JSON object.")
        if data.get("version") != 3:
            raise ValueError(f"Unsupported session version: {data.get('version')!r}")
        if not isinstance(data.get("mrz"), dict):
            raise ValueError("Session file missing or invalid 'mrz' section.")
        if not isinstance(data.get("ef_raw"), dict):
            raise ValueError("Session file missing or invalid 'ef_raw' section.")
        if "mf_ef_raw" in data and not isinstance(data.get("mf_ef_raw"), dict):
            raise ValueError("Session file 'mf_ef_raw' section must be an object.")
        if not isinstance(data.get("apdu_history", []), list):
            raise ValueError("Session file 'apdu_history' must be a list.")
        if "capture_context" in data and not isinstance(data.get("capture_context"), dict):
            raise ValueError("Session file 'capture_context' section must be an object.")
