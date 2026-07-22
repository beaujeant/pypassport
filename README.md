# pypassport

A Python library for reading, analysing, and researching electronic passports (ePassports) that conform to **ICAO Doc 9303**. Initially developed by the Information Security Group (ISG) at UCLouvain as a research platform for studying ePassport security.

This repository contains two complementary projects:

| Project | Description |
|---------|-------------|
| [`pypassport/`](./pypassport/) | Core Python library — parses ICAO 9303 LDS files, performs BAC / supported PACE / authentication flows, and communicates with ePassports over RFID/NFC via a PC/SC reader |
| [`epassportviewer/`](./epassportviewer/) | Desktop GUI — reads and displays passport data and provides APDU traffic, forge, intercept, security-report, fuzzing, and attack workflows on top of `pypassport` |

`pypassport` is the standalone library. `ePassportViewer` is an optional GUI that depends on it.

---

## Background

Electronic passports (ePassports, eMRTDs) embed a contactless chip that stores biographic and biometric data protected by the cryptographic mechanisms defined in ICAO Doc 9303. These include:

- **BAC** (Basic Access Control) and **PACE** for access control
- **Passive Authentication** for verifying document integrity via a PKI chain
- **Active Authentication** for detecting chip cloning

This toolkit implements BAC, the supported PACE subset, Passive
Authentication, and Active Authentication, and also provides research tooling
for testing known security vulnerabilities in deployed passports.

---

## Repository structure

```
./
├── pypassport/                 # Core library (installable on its own)
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/
│   │   └── pypassport/         # Library source package
│   │       ├── doc9303/        # ICAO 9303 protocol implementations
│   │       └── attacks/        # Security research modules
│   └── tests/                  # Test scripts and fixtures
│
├── epassportviewer/            # GUI application (requires pypassport)
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

This repo is a [uv workspace](https://docs.astral.sh/uv/concepts/workspaces/) and requires Python 3.9 or newer. The recommended way to install is with [`uv`](https://github.com/astral-sh/uv):

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
# Offline parsing / protocol code only
uv sync --package pypassport

# Add PC/SC reader support for physical passports
uv sync --package pypassport --extra reader
```

### Core library + GUI

```bash
uv sync

# Launch the GUI from the managed environment
uv run epassportviewer
```

### Without uv (plain pip)

```bash
python -m pip install -e "./pypassport[reader]" -e ./epassportviewer
```

---

## System dependencies

Reading a physical passport requires a **PC/SC smart card service**, the optional
`pypassport[reader]` extra, and a compatible **NFC reader**. Offline parsing,
capture reporting, and passive verification do not need PC/SC. The GUI
additionally needs **Tkinter**.

### PC/SC smart card service

| Platform | Command |
|----------|---------|
| **macOS** | Built into macOS — no extra package needed |
| **Windows** | Built into Windows — install your reader's vendor driver |
| Arch / Manjaro | `sudo pacman -S pcsclite ccid` |
| Debian / Ubuntu | `sudo apt install pcscd pcsc-tools libccid` |
| Fedora | `sudo dnf install pcsc-lite pcsc-lite-ccid` |

See [`pypassport/README.md`](./pypassport/README.md) for ACR122U and PC/SC
troubleshooting.

If `pyscard` has to be built from source, also install `libpcsclite-dev` on
Debian / Ubuntu or `pcsc-lite-devel` on Fedora; packaged wheels do not need the
headers.

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
from pypassport import EPassport, reader

r = reader.get_reader()
if r is None:
    raise RuntimeError("No PC/SC reader found")

# MRZ fields: (document number, date of birth YYMMDD, expiry date YYMMDD)
mrz = ("EP123456", "850101", "260101")
ep = EPassport(r, mrz, select_aid=False)
ep.open(access_control="auto")

dg1 = ep["DG1"]         # parsed MRZ data
faces = ep.get_faces()  # raw JPEG / JPEG2000 face images from DG2
```

See [`pypassport/README.md`](./pypassport/README.md) for library API details and
usage examples.

### Running the GUI

```bash
uv run epassportviewer            # recommended from the repo root
uv run python -m epassportviewer  # equivalent module form

# In an activated pip environment:
epassportviewer
```

### Verifying authenticity (View tab)

The **View** tab's **Verify Signature** and **Active Authentication** controls
run the two genuine ICAO 9303 checks after a passport has been read, using the
MRZ / CAN entered at the top of the window:

- **Active Authentication** — challenges the chip to prove it holds the private
  key matching DG15, defeating chip cloning.
- **Passive Authentication** — verifies the issuing country's signature over the
  data (EF.SOD), chains the Document Signer certificate to a trusted **CSCA**,
  and confirms the hashes of the data groups that were read match the SOD.

The certificate-chain check needs the issuing countries' **Country Signing CA
(CSCA)** certificates. When an issuing state has published its CSCA through
ICAO, it is available in the [ICAO Master List](https://www.icao.int/icao-pkd/icao-master-list);
otherwise use that state's national PKI. Drop the downloaded Master List
(`.ml`) or individual CSCA certificates (`.cer`, `.crt`, `.pem`, `.der`) into a
folder, then point the app at it via **Configure → Settings → CSCA certificate
directory** (or the *Browse…* button in the panel). The choice is remembered
across runs.

---

## PACE support

PACE (Password Authenticated Connection Establishment) is implemented for the
**ECDH Generic Mapping** variants with AES session keys and Brainpool P-256-r1
domain parameters:

| OID | Algorithm | Status |
|-----|-----------|--------|
| `0.4.0.127.0.7.2.2.4.2.2` | ECDH-GM / Brainpool P-256-r1 / AES-128-CBC-CMAC | **Supported** |
| `0.4.0.127.0.7.2.2.4.2.3` | ECDH-GM / Brainpool P-256-r1 / AES-192-CBC-CMAC | **Supported** |
| `0.4.0.127.0.7.2.2.4.2.4` | ECDH-GM / Brainpool P-256-r1 / AES-256-CBC-CMAC | **Supported** |

The access-control negotiator (`AccessControlNegotiator`) selects PACE
automatically when EF.CardAccess advertises one of those implemented profiles,
and otherwise falls back to BAC when an MRZ is available. DH-based PACE,
Integrated Mapping, CAM, 3DES PACE, and other EC domain parameters are not
implemented. After a successful PACE run, AES-CBC/CMAC Secure Messaging
replaces the 3DES/retail-MAC channel used by BAC.

KDF counters and hash algorithms follow BSI TR-03110 §4.3.3: SHA-1 for AES-128 keys, SHA-256 for AES-192 and AES-256 keys.

## Troubleshooting

### ACR122U not detected by PC/SC (`LIBUSB_ERROR_BUSY`)

The ACR122U uses an NXP PN532 NFC chip internally. On Linux, the kernel's built-in
NFC modules (`pn533_usb`, `pn533`, `nfc`) automatically claim the device at the USB
level before the PC/SC daemon (pcscd) gets a chance to. This causes the reader to fail
with `Can't claim interface: LIBUSB_ERROR_BUSY`.

**1. Ensure PC/SC and a CCID driver are installed:**

Arch / Manjaro:
```bash
sudo pacman -S pcsclite ccid
```

Debian / Ubuntu:
```bash
sudo apt install pcscd pcsc-tools libccid
```

Fedora:
```bash
sudo dnf install pcsc-lite pcsc-lite-ccid
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
