"""Central visual theme for ePassportViewer.

A single place that defines the colour palette, fonts and ttk widget styling so
the whole window looks consistent. Without this, the app mixes themed ``ttk``
widgets (which follow the OS theme — often a dark or grey background) with plain
``tk`` widgets that fall back to stark defaults (white text boxes, black
buttons, tiny fonts). The result is the patchwork of black/grey/white areas and
hard-to-read text the theme is here to eliminate.

Call :func:`apply` once on the root window *before* building any widgets. It
installs a fully restyled ``clam`` theme (chosen because it is bundled with Tk
and is completely recolourable, so the UI stops inheriting the host's dark
mode), bumps every default font to a comfortable size, and sets sensible
defaults for tk-only widgets such as menus and combobox dropdowns.

Plain ``tk`` widgets (Text, Listbox, Canvas, Button, Label) are not covered by
ttk styles, so they read the colour/font tokens below directly, or use the
:func:`style_text` / :func:`style_listbox` helpers.
"""

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk


# ── Colour palette (light, low-glare) ────────────────────────────────────────
BACKGROUND = "#eceff4"  # window / frame background
SURFACE = "#ffffff"  # text areas, lists, entries, cards
SURFACE_ALT = "#dfe4ec"  # subtly raised areas (tab strips, headings)
SURFACE_SUNKEN = "#f4f6fa"  # content wells / read-only fields

BORDER = "#c4ccd8"  # hairline borders and separators
BORDER_STRONG = "#a7b1c2"  # emphasised borders / scrollbar grip

TEXT = "#1f2733"  # primary text (near-black, soft)
TEXT_MUTED = "#5b6573"  # secondary / caption text
TEXT_DISABLED = "#9aa3b2"  # disabled widgets
TEXT_ON_ACCENT = "#ffffff"  # text on the accent colour

ACCENT = "#2f6feb"  # primary blue (selected tab, primary buttons)
ACCENT_HOVER = "#215fd6"
ACCENT_ACTIVE = "#1b50ba"
ACCENT_DISABLED = "#a9bbe2"

SELECT_BG = "#d4e2ff"  # selection highlight in lists / text
SELECT_FG = "#1f2733"

OK_BG = "#e7f7ec"  # success row tint (Traffic)
ERR_BG = "#fdebec"  # error row tint (Traffic)
WARN_BG = "#ffe8cc"  # warning / not-verifiable tint
ERROR = "#c43d4b"  # validation border / destructive emphasis


# ── Fonts (real tuples are filled in by apply() once a root exists) ───────────
FONT_BASE = ("", 11)
FONT_BOLD = ("", 11, "bold")
FONT_SMALL = ("", 10)
FONT_MONO = ("", 11)
FONT_H1 = ("", 16, "bold")
FONT_H2 = ("", 12, "bold")

_BASE_SIZE = 11
_MONO_SIZE = 11


def _init_fonts():
    """Bump every standard named font and publish the font tokens above.

    Reconfiguring the ``Tk*Font`` named fonts grows every default-font widget
    (labels, buttons, menus, entries) in one shot; the explicit tuples are for
    the handful of widgets that need a specific size/weight.
    """
    global FONT_BASE, FONT_BOLD, FONT_SMALL, FONT_MONO, FONT_H1, FONT_H2

    def cfg(name, **kw):
        try:
            tkfont.nametofont(name).configure(**kw)
        except tk.TclError:
            pass

    # Resolve the real family names already in use so we never name a font that
    # the platform lacks (Tk would silently substitute, but this keeps things
    # predictable across the UI and proportional/monospace stay distinct).
    ui_family = tkfont.nametofont("TkDefaultFont").actual("family")
    mono_family = tkfont.nametofont("TkFixedFont").actual("family")

    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkIconFont", "TkCaptionFont"):
        cfg(name, family=ui_family, size=_BASE_SIZE)
    cfg("TkSmallCaptionFont", family=ui_family, size=_BASE_SIZE - 1)
    cfg("TkTooltipFont", family=ui_family, size=_BASE_SIZE - 1)
    cfg("TkFixedFont", family=mono_family, size=_MONO_SIZE)

    FONT_BASE = (ui_family, _BASE_SIZE)
    FONT_BOLD = (ui_family, _BASE_SIZE, "bold")
    FONT_SMALL = (ui_family, _BASE_SIZE - 1)
    FONT_MONO = (mono_family, _MONO_SIZE)
    FONT_H1 = (ui_family, _BASE_SIZE + 5, "bold")
    FONT_H2 = (ui_family, _BASE_SIZE + 1, "bold")


def _init_styles(style):
    """Install and recolour the clam theme for every ttk widget we use."""
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass  # clam should always be present; fall back to whatever is active.

    # Base settings inherited by every ttk widget.
    style.configure(
        ".",
        background=BACKGROUND,
        foreground=TEXT,
        fieldbackground=SURFACE,
        font=FONT_BASE,
        bordercolor=BORDER,
        lightcolor=SURFACE,
        darkcolor=BORDER,
        troughcolor=SURFACE_ALT,
        focuscolor=ACCENT,
        relief="flat",
    )

    style.configure("TFrame", background=BACKGROUND)

    style.configure("TLabel", background=BACKGROUND, foreground=TEXT)
    style.configure("Muted.TLabel", background=BACKGROUND, foreground=TEXT_MUTED)
    style.configure("Caption.TLabel", background=BACKGROUND, foreground=TEXT_MUTED, font=FONT_BOLD)
    style.configure("H1.TLabel", background=BACKGROUND, foreground=TEXT, font=FONT_H1)
    style.configure("H2.TLabel", background=BACKGROUND, foreground=TEXT, font=FONT_H2)

    # Grouping frames — a hairline box with an accent-coloured title.
    style.configure("TLabelframe", background=BACKGROUND, bordercolor=BORDER, relief="solid", borderwidth=1)
    style.configure("TLabelframe.Label", background=BACKGROUND, foreground=ACCENT, font=FONT_BOLD)

    # Buttons — flat, with a clear hover/press feedback.
    style.configure(
        "TButton",
        background=SURFACE_ALT,
        foreground=TEXT,
        bordercolor=BORDER,
        relief="flat",
        padding=(12, 6),
        font=FONT_BASE,
        focusthickness=1,
        focuscolor=ACCENT,
    )
    style.map(
        "TButton",
        background=[("disabled", SURFACE_SUNKEN), ("pressed", BORDER_STRONG), ("active", BORDER)],
        foreground=[("disabled", TEXT_DISABLED)],
        bordercolor=[("focus", ACCENT)],
    )

    # Primary call-to-action button (Read, Send APDU, ...).
    style.configure("Accent.TButton", background=ACCENT, foreground=TEXT_ON_ACCENT, font=FONT_BOLD)
    style.map(
        "Accent.TButton",
        background=[("disabled", ACCENT_DISABLED), ("pressed", ACCENT_ACTIVE), ("active", ACCENT_HOVER)],
        foreground=[("disabled", SURFACE)],
    )

    # Tabs.
    style.configure("TNotebook", background=BACKGROUND, borderwidth=0, tabmargins=(8, 6, 8, 0))
    style.configure(
        "TNotebook.Tab",
        background=SURFACE_ALT,
        foreground=TEXT_MUTED,
        padding=(18, 9),
        font=FONT_BASE,
        bordercolor=BORDER,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", SURFACE), ("active", BORDER)],
        foreground=[("selected", ACCENT)],
        padding=[],
        expand=[],
    )

    # Text entries.
    style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT, bordercolor=BORDER, insertcolor=TEXT, padding=5)
    style.map(
        "TEntry",
        bordercolor=[("invalid", ERROR), ("focus", ACCENT)],
        lightcolor=[("invalid", ERROR), ("focus", ACCENT)],
        darkcolor=[("invalid", ERROR)],
        foreground=[("disabled", TEXT_DISABLED), ("readonly", TEXT)],
        fieldbackground=[("readonly", SURFACE_SUNKEN), ("disabled", SURFACE_SUNKEN)],
    )

    # Dropdowns.
    style.configure(
        "TCombobox",
        fieldbackground=SURFACE,
        background=SURFACE_ALT,
        foreground=TEXT,
        arrowcolor=TEXT,
        bordercolor=BORDER,
        padding=5,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", SURFACE), ("disabled", SURFACE_SUNKEN)],
        foreground=[("readonly", TEXT), ("disabled", TEXT_DISABLED)],
        selectbackground=[("readonly", SURFACE)],
        selectforeground=[("readonly", TEXT)],
        bordercolor=[("focus", ACCENT)],
        lightcolor=[("focus", ACCENT)],
        arrowcolor=[("disabled", TEXT_DISABLED)],
    )

    # Checkboxes (clam draws the box with indicatorbackground/-foreground).
    style.configure(
        "TCheckbutton",
        background=BACKGROUND,
        foreground=TEXT,
        focuscolor=ACCENT,
        indicatorbackground=SURFACE,
        indicatorforeground=TEXT_ON_ACCENT,
        bordercolor=BORDER_STRONG,
        padding=3,
    )
    style.map(
        "TCheckbutton",
        background=[("active", BACKGROUND)],
        indicatorbackground=[("selected", ACCENT), ("pressed", ACCENT_HOVER), ("disabled", SURFACE_SUNKEN)],
        indicatorforeground=[("selected", TEXT_ON_ACCENT)],
        bordercolor=[("focus", ACCENT)],
        foreground=[("disabled", TEXT_DISABLED)],
    )

    # Tables.
    style.configure(
        "Treeview",
        background=SURFACE,
        fieldbackground=SURFACE,
        foreground=TEXT,
        rowheight=_BASE_SIZE * 2 + 8,
        bordercolor=BORDER,
        relief="flat",
        font=FONT_BASE,
    )
    style.map(
        "Treeview",
        background=[("selected", SELECT_BG)],
        foreground=[("selected", SELECT_FG)],
    )
    style.configure(
        "Treeview.Heading", background=SURFACE_ALT, foreground=TEXT, font=FONT_BOLD, relief="flat", padding=(8, 5)
    )
    style.map("Treeview.Heading", background=[("active", BORDER)])

    # Scrollbars — slim and unobtrusive.
    style.configure(
        "TScrollbar",
        background=SURFACE_ALT,
        troughcolor=BACKGROUND,
        bordercolor=BACKGROUND,
        arrowcolor=TEXT_MUTED,
        relief="flat",
        borderwidth=0,
    )
    style.map(
        "TScrollbar",
        background=[("active", BORDER_STRONG), ("pressed", BORDER_STRONG)],
        arrowcolor=[("disabled", BORDER)],
    )

    style.configure("TSeparator", background=BORDER)


def _init_options(root):
    """Style the widgets ttk cannot reach (menus, combobox popups, tk defaults)."""
    # tk.Menu is not a themed widget — recolour it through the option database.
    root.option_add("*Menu.background", SURFACE)
    root.option_add("*Menu.foreground", TEXT)
    root.option_add("*Menu.activeBackground", ACCENT)
    root.option_add("*Menu.activeForeground", TEXT_ON_ACCENT)
    root.option_add("*Menu.selectColor", ACCENT)
    root.option_add("*Menu.relief", "flat")
    root.option_add("*Menu.borderWidth", 1)
    root.option_add("*Menu.activeBorderWidth", 0)

    # The combobox drop-down list is a tk.Listbox reached only via the option DB.
    root.option_add("*TCombobox*Listbox.background", SURFACE)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", TEXT_ON_ACCENT)

    # Sensible fallbacks for any tk widget not styled explicitly.
    root.option_add("*selectBackground", SELECT_BG)
    root.option_add("*selectForeground", SELECT_FG)
    root.option_add("*insertBackground", TEXT)


def apply(root):
    """Apply the full theme to *root*. Call once, before building widgets."""
    _init_fonts()
    style = ttk.Style(root)
    _init_styles(style)
    _init_options(root)
    root.configure(background=BACKGROUND)
    return style


# ── Helpers for plain tk widgets (not covered by ttk styles) ─────────────────
def style_text(widget, *, mono=True, padx=8, pady=6):
    """Give a ``tk.Text`` / ``ScrolledText`` the themed look."""
    widget.configure(
        background=SURFACE,
        foreground=TEXT,
        insertbackground=TEXT,
        selectbackground=SELECT_BG,
        selectforeground=SELECT_FG,
        relief="flat",
        borderwidth=0,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=BORDER,
        padx=padx,
        pady=pady,
        font=FONT_MONO if mono else FONT_BASE,
    )
    return widget


def style_listbox(widget):
    """Give a ``tk.Listbox`` the themed look."""
    widget.configure(
        background=SURFACE,
        foreground=TEXT,
        selectbackground=SELECT_BG,
        selectforeground=SELECT_FG,
        relief="flat",
        borderwidth=0,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=BORDER,
        activestyle="none",
        font=FONT_BASE,
    )
    return widget
