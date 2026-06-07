# pypassport

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

This repo is a [uv workspace](https://docs.astral.sh/uv/concepts/workspaces/). The recommended way to install is with [`uv`](https://github.com/astral-sh/uv):

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install everything (both packages + all deps) into a managed .venv
uv sync

# Verify
uv run python -c "import pypassport; print('OK')"
```

### Core library only

```bash
uv sync --package pypassport
```

### Core library + GUI

```bash
uv sync
```

### Without uv (plain pip)

```bash
python -m pip install -e ./pypassport -e ./ePassportViewer
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

---

## PACE support

PACE (Password Authenticated Connection Establishment) is now fully implemented for the **ECDH Generic Mapping** variants with AES session keys. These are the variants advertised by modern EU passports.

| OID | Algorithm | Status |
|-----|-----------|--------|
| `0.4.0.127.0.7.2.2.4.2.2` | ECDH-GM / Brainpool P-256-r1 / AES-128-CBC-CMAC | **Supported** |
| `0.4.0.127.0.7.2.2.4.2.3` | ECDH-GM / Brainpool P-256-r1 / AES-192-CBC-CMAC | **Supported** |
| `0.4.0.127.0.7.2.2.4.2.4` | ECDH-GM / Brainpool P-256-r1 / AES-256-CBC-CMAC | **Supported** |

The access-control negotiator (`AccessControlNegotiator`) selects PACE automatically when the chip advertises a supported OID in EF.CardAccess, and falls back to BAC for older chips. After a successful PACE run, AES-CBC/CMAC Secure Messaging replaces the 3DES/retail-MAC channel used by BAC.

KDF counters and hash algorithms follow BSI TR-03110 §4.3.3: SHA-1 for AES-128 keys, SHA-256 for AES-192 and AES-256 keys.
