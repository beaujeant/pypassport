# ePassportViewer

Desktop GUI application for reading, displaying, and analysing electronic passports (ePassports / eMRTDs).

Built with Python, Tkinter, and Pillow. Depends on the [`pypassport`](../pypassport/) core library from the same repository.

---

## Features

The window is organised as five tabs, all working off a single shared
passport session: reading once on **View** keeps the Secure Messaging channel
live for **Forge**, **Intercept** and **Security** instead of re-running
BAC/PACE per action. The MRZ (Number / DoB / Expiry) and optional CAN entered
at the top of the window feed every tab.

### View tab

Reads and displays the passport holder's data directly from the chip:

- Holder name, nationality, document number, date of birth, date of expiry
- Facial photograph (DG2, JPEG or JPEG2000)
- Per-EF inspector for EF.COM, EF.SOD and every data group, including files
  advertised in EF.COM but not readable

### Traffic tab

A live log of every command/response APDU exchanged with the chip — from
**every** tab — in a Burp-style table:

- Decoded view plus the on-the-wire (SM-protected) bytes
- Filter by text, errors-only, hide-SM, or by source (read / forge / security / fuzz)
- Per-transaction comments and colour highlights; copy as hex or as a
  ready-to-paste `APDUCommand(...)`; send any transaction to the Forge tab

### Forge tab

Hand-craft and replay APDUs (Burp-Repeater style numbered request tabs):

- Fielded or raw-hex editing, common-request presets, response hex dump
- Send through the active Secure Messaging channel or force a one-off
  plaintext APDU without tearing the channel down
- Reset the card and re-run BAC/PACE to recover a wedged SM session

### Intercept tab

A Burp-style proxy for the card: hold each command APDU in flight to inspect,
edit, forward or drop it, or define match-&-replace rules that rewrite
commands automatically.

### Security tab

Summarises the current View session and keeps the research tools in one place:

- Reflects **Active / Passive Authentication** results from the View tab,
  including clone resistance and the EF.SOD → DSC → CSCA signature chain
  (needs a CSCA certificate directory)
- Exportable findings, protocol summaries, parsed files, deterministic APDU
  fuzzing campaigns, and reusable probes
- An **Attacks** subtab for **MAC traceability**, **AA-before-BAC**,
  **sign-everything oracle**, **AA modulus traceability**, and **BAC brute
  force** (online and offline)
- An **Advanced protocols** subtab for application-qualified filesystem/FID
  exploration, bounded arbitrary EF reads, SOD/CardSecurity-backed Chip
  Authentication, and CVC/CHAT-based Terminal Authentication

### Sessions & MRZ history

The **File** menu saves and restores a whole research session — credentials,
the EF view, the complete APDU history, and Security capture context such as
ATR/UID and verification results — to a `.eps` file, so traffic can be replayed
into Forge offline. Reopening a session does not restore live Secure Messaging
keys or a card connection; re-read the passport before sending new live
commands. Previously entered MRZs are remembered for quick re-connection.

---

## Installation

### From the monorepo root

The repository is a `uv` workspace. The shortest path to a runnable GUI is:

```bash
uv sync
uv run epassportviewer
```

For a plain `pip` environment:

```bash
python -m venv .venv
source .venv/bin/activate     # Linux / macOS
# .venv\Scripts\activate      # Windows

python -m pip install --upgrade pip
python -m pip install -e "./pypassport[reader]" -e ./epassportviewer
```

---

## Running the application

```bash
uv run epassportviewer
uv run python -m epassportviewer

# In an activated pip environment:
epassportviewer
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
sudo apt install pcscd pcsc-tools libccid

# Arch / Manjaro
sudo pacman -S pcsclite ccid

# Fedora
sudo dnf install pcsc-lite pcsc-lite-ccid

# macOS — PC/SC is built into macOS; no extra package needed.
# Windows — install your reader's vendor driver; PC/SC is built into Windows.
```

If `pyscard` has to be built from source, also install `libpcsclite-dev` on
Debian / Ubuntu or `pcsc-lite-devel` on Fedora; packaged wheels do not need the
headers.

For ACR122U and PC/SC troubleshooting, see
[`pypassport/README.md`](../pypassport/README.md).

---

## Troubleshooting

**`ImportError: libtk8.6.so` or `No module named '_tkinter'`**

Install the OS Tk package for your distro (see Tkinter / Tk section above).

**"Failure to list readers: Service not Available."**

```bash
sudo systemctl restart pcscd
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
| `pypassport[reader]` | Core ePassport protocol library plus PC/SC reader support |
| `Pillow` | Decodes and displays the JPEG/JPEG2000 facial image from DG2 |
| `tkinter` | GUI framework — ships with Python but needs a separate OS package on most systems |
| PC/SC service | `pcscd` + NFC reader driver |

---

## Project structure

```
epassportviewer/
├── pyproject.toml
├── README.md
├── src/
│   └── epassportviewer/
│       ├── __init__.py
│       ├── __main__.py          # Entry point (python -m epassportviewer)
│       ├── app.py               # Main window; shared session, reader handling, MRZ input
│       ├── theme.py             # Central palette, fonts and ttk styling
│       ├── viewer.py            # View tab — passport data, photo, EF inspector, sessions
│       ├── traffic.py           # Traffic tab — APDU history, filtering, send-to-Forge
│       ├── forge.py             # Forge tab — hand-craft / replay APDUs
│       ├── intercept.py         # Intercept tab — hold / edit / drop APDUs in flight
│       ├── security.py          # Security tab — reports, files, probes, subtab host
│       ├── fuzzing.py           # Security Fuzzing subtab — APDU mutation campaigns
│       ├── analyse.py           # Security Attacks subtab
│       ├── hexdump.py           # Coloured hex dump renderer
│       ├── apdu_format.py       # APDU field formatting / parsing helpers
│       ├── settings.py          # Persistent settings (CSCA directory)
│       ├── log.py               # Log viewer pane
│       ├── menu.py              # Menu bar (File, Configure, Help)
│       └── resources/
│           ├── gadgets/
│           │   └── placeholder.py   # Custom Tkinter placeholder widget
│           └── img/                 # Toolbar icon PNGs
└── tests/
```
