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

## Troubleshooting

### ACR122U not detected by PC/SC (`LIBUSB_ERROR_BUSY`)

The ACR122U uses an NXP PN532 NFC chip internally. On Linux, the kernel's built-in
NFC modules (`pn533_usb`, `pn533`, `nfc`) automatically claim the device at the USB
level before the PC/SC daemon (pcscd) gets a chance to. This causes the reader to fail
with `Can't claim interface: LIBUSB_ERROR_BUSY`.

**1. Install the driver:**

Arch / Manjaro:
```bash
yay -S acsccid
```

Debian / Ubuntu:
```bash
sudo apt install pcscd acsccid pcsc-tools
```

**2. Blacklist the conflicting kernel modules:**

```bash
sudo tee /etc/modprobe.d/blacklist-nfc.conf <<EOF
blacklist pn533_usb
blacklist pn533
blacklist nfc
EOF
```

**3. Unload them for the current session (no reboot needed):**

```bash
sudo modprobe -r pn533_usb pn533 nfc
```

**4. Make sure only one pcscd instance is running:**

```bash
sudo systemctl stop pcscd pcscd.socket
sudo killall pcscd 2>/dev/null
sudo systemctl start pcscd
```

**5. Verify the reader is detected:**

```bash
pcsc_scan
```

---

### Reader detected but card not found

- Make sure the passport (or card) is placed **flat and centred** on the reader.
- The ACR122U has a short read range — keep the card still and within a few mm of the surface.
- Try a different USB port (preferably USB 2.0; some USB 3.0 ports cause instability).

### Stale pcscd process holding the device

If the reader was working and suddenly stops after a suspend/resume or replug, a stale
pcscd process may still be holding the USB interface:

```bash
sudo fuser /dev/bus/usb/$(lsusb -d 072f:2200 | awk '{print $2"/"$4}' | tr -d :)
```

Kill any stale PID shown, then restart pcscd normally.
