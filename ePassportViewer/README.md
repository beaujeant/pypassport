# ePassportViewer

Desktop GUI application for reading and analysing electronic passports (ePassports).

Built with Python, Tkinter, and Pillow. Depends on the [`pypassport`](../pypassport/) core library from the same repository.

---

## What it does

* Reads MRZ data and the facial image from an ePassport (DG1, DG2).
* Provides tabbed panes for:
  * **View** — displays passport holder information and photo.
  * **Attacks** — runs Error Fingerprinting and Active Authentication attack tools.
  * **Custom** — sends raw APDU commands, performs BAC, generates keys, and runs crypto utilities.
* Maintains an MRZ history for quick re-connection.

---

## Dependencies

| Requirement | Notes |
|-------------|-------|
| `pypassport` | Core library — must be installed from this repo |
| `Pillow` | Image display in the GUI |
| `pycryptodome` | 3DES operations in the Custom tab |
| `tkinter` | GUI framework — ships with Python but needs a separate OS package on most systems (see below) |
| PC/SC service | `pcscd` + reader driver — see below |

---

## Installation (local development from this monorepo)

```bash
# From the repository root
python -m venv .venv
source .venv/bin/activate   # Linux / macOS

pip install --upgrade pip

# Install the core library in editable mode first
pip install -e ./pypassport

# Install the GUI in editable mode
pip install -e ./ePassportViewer
```

---

## Running the application

```bash
# Via the installed entry-point script
epassportviewer

# Or as a Python module
python -m epassportviewer
```

---

## System dependencies

### Tkinter / Tk

Tkinter is part of the Python standard library, but the underlying Tk graphical toolkit is a separate OS-level package that pip/uv cannot install for you. If you see `ImportError: libtk8.6.so` or `No module named '_tkinter'`, install Tk for your platform:

**macOS**

The `python.org` installer bundles Tk. If you installed Python via Homebrew it does not, so install the Homebrew Tk:

```bash
brew install python-tk
# or, for a specific Python version:
brew install python-tk@3.13
```

**Windows**

Tk is bundled in the official `python.org` installer — make sure **"tcl/tk and IDLE"** is ticked during installation. If you used a minimal install without it, re-run the installer, choose *Modify*, and enable that component.

**Linux**

| Distro | Command |
|--------|---------|
| Arch / Manjaro | `sudo pacman -S tk` |
| Debian / Ubuntu / Mint | `sudo apt install python3-tk` |
| Fedora / RHEL / CentOS | `sudo dnf install python3-tkinter` |
| openSUSE | `sudo zypper install python3-tk` |

> **Note:** if you are running Python from a custom build or a version manager (pyenv, asdf, uv-managed Python), you may need to rebuild Python with Tk support or install Tk *before* building Python so the `_tkinter` extension is compiled in.

---

### PC/SC smart card service

A PC/SC smart card service and a compatible NFC reader are required.

```bash
# Debian / Ubuntu
sudo apt install pcscd libusb-dev

# Arch / Manjaro
sudo pacman -S pcsclite

# Fedora / RHEL
sudo dnf install pcsc-lite pcsc-lite-libs

# macOS — PCSC is built into macOS; no extra package needed.
# Windows — install the reader's vendor driver; PCSC is built into Windows.
```

For full reader driver installation instructions (e.g. ACR122U), see [`pypassport/README.md`](../pypassport/README.md).

### Troubleshooting

**`ImportError: libtk8.6.so` or `No module named '_tkinter'`**

Install the OS Tk package for your distro (see the Tkinter section above).

**"Failure to list readers: Service not Available."**

```bash
sudo service pcscd restart
```

---

## Project structure

```
ePassportViewer/
├── pyproject.toml
├── README.md
├── src/
│   └── epassportviewer/
│       ├── __init__.py
│       ├── __main__.py         # Entry point (python -m epassportviewer)
│       ├── app.py              # Main application window
│       ├── attacks.py          # Attacks tab
│       ├── custom.py           # Custom APDU / tools tab
│       ├── log.py              # Log viewer pane
│       ├── menu.py             # Menu bar
│       ├── viewer.py           # Passport data view tab
│       └── resources/
│           ├── gadgets/
│           │   └── placeholder.py   # Placeholder entry widget
│           └── img/                 # Toolbar icons (PNG)
└── tests/
