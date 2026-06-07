# ePassportViewer

Desktop GUI application for reading, displaying, and analysing electronic passports (ePassports / eMRTDs).

Built with Python, Tkinter, and Pillow. Depends on the [`pypassport`](../pypassport/) core library from the same repository.

---

## Features

### View tab

Reads and displays the passport holder's data directly from the chip:

- Holder name, nationality, document number, date of birth, date of expiry
- Facial photograph (DG2, JPEG or JPEG2000)
- Parsed MRZ content (DG1)
- Real-time log output panel

### Attacks tab

Runs security analysis tools against the connected passport chip. Each tool operates as a sub-tab:

| Sub-tab | Description |
|---------|-------------|
| **Error Fingerprinting** | Sends probe APDUs and inspects non-standard error responses to identify the chip manufacturer and issuing country without authentication |
| **Brute Force** | Tests BAC key space by iterating over configurable ranges of document number, date of birth, and expiry date |
| **MAC Traceability** | Tests the Chothia & Smirnov attack — determines whether a previously captured BAC message/MAC pair can uniquely identify the passport chip |
| **Active Authentication** | Tests whether AA can be invoked before BAC (leaking traceability information) and verifies the AA signature |

### Custom tab

Low-level tools for manual testing and protocol debugging:

- **Raw APDU** — send arbitrary ISO 7816-4 APDUs and inspect the response
- **BAC** — manually trigger Basic Access Control with custom MRZ input
- **3DES / AES** — encrypt / decrypt data with custom keys
- **SHA-1 / XOR** — hash and XOR utilities
- **SSC** — inspect and modify the Send Sequence Counter used by Secure Messaging

### MRZ history

The application maintains a history of previously entered MRZ values for quick re-connection across sessions.

---

## Installation

### From the monorepo root

```bash
python -m venv .venv
source .venv/bin/activate     # Linux / macOS
# .venv\Scripts\activate      # Windows

pip install --upgrade pip

# Install the core library first
pip install -e ./pypassport

# Then install the GUI
pip install -e ./ePassportViewer
```

---

## Running the application

```bash
# Via the installed entry-point script (after pip install)
epassportviewer

# Or as a Python module
python -m epassportviewer
```

---

## System dependencies

### Tkinter / Tk

Tkinter is part of the Python standard library, but the underlying Tk graphical toolkit is a separate OS-level package that `pip` cannot install for you. If you see `ImportError: libtk8.6.so` or `No module named '_tkinter'`, install Tk for your platform:

**macOS**

The `python.org` installer bundles Tk. If you installed Python via Homebrew it does not, so install the Homebrew Tk:

```bash
brew install python-tk
# or, for a specific Python version:
brew install python-tk@3.13
```

**Windows**

Tk is bundled in the official `python.org` installer. Make sure **"tcl/tk and IDLE"** is ticked during installation. If you used a minimal install, re-run the installer, choose *Modify*, and enable that component.

**Linux**

| Distro | Command |
|--------|---------|
| Arch / Manjaro | `sudo pacman -S tk` |
| Debian / Ubuntu / Mint | `sudo apt install python3-tk` |
| Fedora / RHEL / CentOS | `sudo dnf install python3-tkinter` |
| openSUSE | `sudo zypper install python3-tk` |

> If you are running Python from a version manager (pyenv, asdf, uv) you may need to rebuild Python with Tk support, or install Tk *before* building Python.

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

# macOS — PC/SC is built into macOS; no extra package needed.
# Windows — install your reader's vendor driver; PC/SC is built into Windows.
```

For full reader driver installation instructions (e.g. ACR122U), see [`pypassport/README.md`](../pypassport/README.md).

---

## Troubleshooting

**`ImportError: libtk8.6.so` or `No module named '_tkinter'`**

Install the OS Tk package for your distro (see Tkinter / Tk section above).

**"Failure to list readers: Service not Available."**

```bash
sudo service pcscd restart
```

**Blank photo / image not displayed**

Ensure `Pillow` is installed in the same virtual environment as `epassportviewer`:

```bash
pip install Pillow
```

---

## Dependencies

| Requirement | Purpose |
|-------------|---------|
| `pypassport` | Core ePassport protocol library — must be installed from this repo |
| `Pillow` | Decodes and displays the JPEG/JPEG2000 facial image from DG2 |
| `pycryptodome` | 3DES operations in the Custom tab crypto utilities |
| `tkinter` | GUI framework — ships with Python but needs a separate OS package on most systems |
| PC/SC service | `pcscd` + NFC reader driver |

---

## Project structure

```
ePassportViewer/
├── pyproject.toml
├── README.md
├── src/
│   └── epassportviewer/
│       ├── __init__.py
│       ├── __main__.py          # Entry point (python -m epassportviewer)
│       ├── app.py               # Main application window; MRZ input, history, logging
│       ├── viewer.py            # View tab — displays passport data and photo
│       ├── attacks.py           # Attacks tab — security analysis sub-tabs
│       ├── custom.py            # Custom tab — raw APDUs, crypto tools
│       ├── log.py               # Log viewer pane
│       ├── menu.py              # Menu bar (File, Configure, Help)
│       └── resources/
│           ├── gadgets/
│           │   └── placeholder.py   # Custom Tkinter placeholder widget
│           └── img/                 # Toolbar icon PNGs
└── tests/
