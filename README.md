# pypassport

A Python library for reading, analysing, and researching electronic passports (ePassports) that conform to **ICAO Doc 9303**. Initially developed by the Information Security Group (ISG) at UCLouvain as a research platform for studying ePassport security.

This repository contains two complementary projects:

| Project | Description |
|---------|-------------|
| [`pypassport/`](./pypassport/) | Core Python library — parses ICAO 9303 LDS files, performs BAC / supported PACE / authentication flows, and communicates with ePassports over RFID/NFC via a PC/SC reader |
| [`epassportviewer/`](./epassportviewer/) | Desktop GUI — reads and displays passport data and provides APDU traffic, forge, intercept, security-report, fuzzing, and attack workflows on top of `pypassport` |
| [`epassportmcp/`](./epassportmcp/) | Local MCP bridge — forwards lazy workflows to the running ePassportViewer process and its reader/session |

`pypassport` is the standalone library. `ePassportViewer` is an optional GUI that depends on it, and
`epassportviewer-mcp` is the optional local MCP integration for external AIs.

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
├── epassportmcp/               # Stateful, lazy-discovery MCP server
├── pyproject.toml              # Monorepo-level tooling (pytest, ruff, mypy, coverage)
├── uv.lock
├── CLAUDE.md
├── README.md                   # This file
└── .gitignore
```

---

## Installation

This repo is a [uv workspace](https://docs.astral.sh/uv/concepts/workspaces/) and requires Python 3.10 or newer. The recommended way to install is with [`uv`](https://github.com/astral-sh/uv):

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

### Running the MCP server

```bash
uv sync
uv run epassportviewer

# This bridge command is normally launched by Codex/Claude, not manually:
uv run --package epassportviewer-mcp epassportviewer-mcp
```

Run ePassportViewer first; it hosts the physical reader/session. The second
command is only the stdio bridge launched by the AI client and does not open
PC/SC itself. Tick **Enable MCP** under **Configure > Settings** in the running viewer to opt in. The viewer
shows connection/card-operation status, asks before high-risk live actions, and
serialises GUI and MCP card workflows on the same Secure Messaging session.

The local MCP lets Codex or Claude assist the running GUI and operate the library's
PACE/BAC, LDS acquisition, authenticity verification, EAC, access-matrix,
hidden-file discovery, traffic, bounded fuzzing, and attack-analysis workflows.
It exposes a small lazy catalog and returns exact status evidence without
putting whole binary data groups in the conversation. See
[`epassportmcp/README.md`](./epassportmcp/README.md) for the Codex and Claude
installation subchapter and the raw/protected APDU channel model.

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

## Advanced access and authentication

PACE supports DH/ECDH Generic and Integrated Mapping, ECDH Chip Authentication
Mapping, the standard parameter IDs (with domain suitability checks),
issuer-supplied explicit parameters, AES-128/192/256 and 3DES, MRZ/CAN/PIN/PUK,
and multiple PACEInfo entries. PACE-CAM decrypts CA data, binds the mapping key
to EF.CardSecurity, and retains the still-required Passive Authentication state.
Automatic mode only enters ordinary BAC for a BAC-only file profile. Any PACE
discovery/profile/authentication failure requires the explicit
`allow_bac_fallback=True` downgrade and is preserved as a high-severity finding.

`EPassport.do_chip_authentication()` runs CA v1/v2 with DH/ECDH and AES/3DES,
using an SOD-authenticated DG14 or signed/trusted EF.CardSecurity. The optional
`do_terminal_authentication()` path parses and validates CVCA/link/DV/IS CVCs,
dates and CHAT rights, sends the certificate/APDU flow when credentials are
provided, and can test that DG3/DG4 rights which were not granted stay denied.

`TrustStore.from_directory()` is the strict PKI entry point. Signed Master Lists
require configured MLSC anchors; paths cover link/intermediate certificates,
certificate roles/critical extensions, CRLs and signed Deviation Lists.

KDF counters and hash algorithms follow BSI TR-03110 §4.3.3: SHA-1 for AES-128 keys, SHA-256 for AES-192 and AES-256 keys.

`FileSystemExplorer` enumerates applications from EF.DIR and probes explicit
`(application, FID, SFI)` references. This keeps EF.SOD separate from
EF.CardSecurity even though both are `011D/77`. The APDU layer supports short
and extended cases under Secure Messaging, 61xx GET RESPONSE, 6Cxx Le repair,
authenticated 62xx/63xx partial responses, odd READ BINARY offsets, command
chaining and bounded reads.

### Interoperability and conformance

`pypassport-conformance` runs a redacted, TR-03105-oriented profile against a
physical document. Credentials are supplied through `EPASSPORT_MRZ` or the
three `EPASSPORT_DOCUMENT_NUMBER`, `EPASSPORT_DATE_OF_BIRTH`, and
`EPASSPORT_DATE_OF_EXPIRY` environment variables (and optional
`EPASSPORT_CAN`), never through command-line arguments. Reports contain check
outcomes and APDU status histograms, but no document bytes, credentials, exact
APDUs, ATR, UID, challenges, keys, or certificate holder references.
The profiles follow the application/LDS and EAC areas of the official
[BSI TR-03105 test plans](https://www.bsi.bund.de/dok/TR-03105-en); this runner
collects interoperability evidence but is not a substitute for accredited
conformity certification or RF layer testing.

```bash
EPASSPORT_MRZ='<full MRZ>' pypassport-conformance \
  --profile .github/conformance/icao-baseline.json \
  --csca-directory /path/to/trusted-csca \
  --report conformance.json
```

The repository includes baseline, modern PACE/CA, and EAC/TA profiles under
`.github/conformance`. A manual hardware-smoke workflow runs them on a
self-hosted runner labelled `epassport-lab`; all document credentials and
ID_PICC values come from runner secrets/environment rather than the workflow
or report.

The desktop Security workbench exposes the same modern protocol engine under
**Advanced protocols**. The MCP actions are `passport.filesystem`,
`passport.read_by_fid`, `security.chip_authentication`,
`security.terminal_authentication`, and `security.conformance`.

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
