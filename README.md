# ePassport Monorepo

A Python library for reading, analysing, and researching electronic passports (ePassports) that conform to **ICAO Doc 9303**. Initially developed by the Information Security Group (ISG) at UCLouvain as a research platform for studying ePassport security.

This repository contains two complementary projects:

| Project | Description |
|---------|-------------|
| [`pypassport/`](./pypassport/) | Core Python library — implements the ICAO 9303 protocol stack and communicates with ePassports over RFID/NFC via a PC/SC reader |
| [`ePassportViewer/`](./ePassportViewer/) | Desktop GUI — reads and displays passport data, runs security analysis tools; built on top of `pypassport` |

`pypassport` is the standalone library. `ePassportViewer` is an optional GUI that depends on it.

---

## Background

Electronic passports (ePassports, eMRTDs) embed a contactless chip that stores biographic and biometric data protected by the cryptographic mechanisms defined in ICAO Doc 9303. These include:

- **BAC** (Basic Access Control) and **PACE** for access control
- **Passive Authentication** for verifying document integrity via a PKI chain
- **Active Authentication** for detecting chip cloning

This toolkit implements those protocols and also provides a research module for testing known security vulnerabilities in deployed passports.

---

## Repository structure

```
./
├── pypassport/                 # Core library (installable on its own)
│   ├── pyproject.toml
│   ├── README.md
│   ├── LICENSE
│   ├── src/
│   │   └── pypassport/         # Library source package
│   │       ├── doc9303/        # ICAO 9303 protocol implementations
│   │       └── attacks/        # Security research modules
│   └── tests/                  # Test scripts and fixtures
│
├── ePassportViewer/            # GUI application (requires pypassport)
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/
│   │   └── epassportviewer/    # Application source package
│   │       └── resources/      # Bundled icons and widgets
│   └── tests/
│
├── pyproject.toml              # Monorepo-level tooling (pytest, ruff, mypy, coverage)
├── uv.lock
├── CLAUDE.md
├── README.md                   # This file
└── .gitignore
```

---

## Installation

### Core library only

```bash
python -m pip install -e ./pypassport
python -c "import pypassport; print('OK')"
```

### Core library + GUI

```bash
python -m pip install -e ./pypassport -e ./ePassportViewer
```

### Recommended: use a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows

pip install --upgrade pip
pip install -e ./pypassport -e ./ePassportViewer
```

---

## System dependencies

Two OS-level components are required regardless of installation method: a **PC/SC smart card service** and a compatible **NFC reader**. The GUI additionally needs **Tkinter**.

### PC/SC smart card service

| Platform | Command |
|----------|---------|
| **macOS** | Built into macOS — no extra package needed |
| **Windows** | Built into Windows — install your reader's vendor driver |
| Arch / Manjaro | `sudo pacman -S pcsclite` |
| Debian / Ubuntu | `sudo apt install pcscd libusb-dev` |
| Fedora / RHEL | `sudo dnf install pcsc-lite` |

See [`pypassport/README.md`](./pypassport/README.md) for reader driver installation (ACR122U and others).

### Tkinter / Tk (GUI only)

Tkinter ships with Python but the underlying Tk library must be installed separately on most systems:

| Platform | Command |
|----------|---------|
| **macOS** (Homebrew Python) | `brew install python-tk` |
| **Windows** | Re-run the `python.org` installer → Modify → enable *tcl/tk and IDLE* |
| Arch / Manjaro | `sudo pacman -S tk` |
| Debian / Ubuntu / Mint | `sudo apt install python3-tk` |
| Fedora / RHEL | `sudo dnf install python3-tkinter` |
| openSUSE | `sudo zypper install python3-tk` |

---

## Quick start

### Reading passport data

```python
from pypassport import reader
from pypassport.epassport import EPassport

r = reader.getReader()

# MRZ fields: (document number, date of birth YYMMDD, expiry date YYMMDD)
ep = EPassport(r, ("EP123456", "850101", "260101"))

dg1 = ep["DG1"]   # MRZ text data
dg2 = ep["DG2"]   # facial image (JPEG / JPEG2000)
```

See [`pypassport/README.md`](./pypassport/README.md) for the full API and usage examples.

### Running the GUI

```bash
epassportviewer            # if installed as a script
# or
python -m epassportviewer  # run as a module
```