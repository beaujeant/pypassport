# ePassport Monorepo

This repository contains two related Python projects for working with electronic passports (ePassports / ICAO Doc 9303):

| Project | Description |
|---------|-------------|
| [`pypassport/`](./pypassport/) | Core Python library — communicates with ePassports over RFID/NFC/PC/SC |
| [`ePassportViewer/`](./ePassportViewer/) | Desktop GUI — displays passport data and sends custom APDUs; built on top of `pypassport` |

`pypassport` is the standalone library. `ePassportViewer` is an optional GUI that depends on it.

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
│   └── tests/                  # Test scripts and fixtures
│
├── ePassportViewer/            # GUI application (requires pypassport)
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/
│   │   └── epassportviewer/    # Application source package
│   │       └── resources/      # Bundled icons and gadgets
│   └── tests/
│
├── pyproject.toml              # Monorepo-level tooling (pytest, ruff, mypy, coverage)
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
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows

pip install --upgrade pip
pip install -e ./pypassport -e ./ePassportViewer
```

---

## System dependencies

Two OS-level dependencies are required for the GUI; `pypassport` only needs the PC/SC service.

### Tkinter / Tk (GUI only)

Tkinter is bundled with Python but the underlying Tk library must be installed separately on most systems:

| Platform | Command |
|----------|---------|
| **macOS** (Homebrew Python) | `brew install python-tk` |
| **Windows** | Re-run the `python.org` installer → Modify → enable *tcl/tk and IDLE* |
| Arch / Manjaro | `sudo pacman -S tk` |
| Debian / Ubuntu / Mint | `sudo apt install python3-tk` |
| Fedora / RHEL | `sudo dnf install python3-tkinter` |
| openSUSE | `sudo zypper install python3-tk` |

### PC/SC smart card service

| Platform | Command |
|----------|---------|
| **macOS** | Built into macOS — no extra package needed |
| **Windows** | Built into Windows — install your reader's vendor driver |
| Arch / Manjaro | `sudo pacman -S pcsclite` |
| Debian / Ubuntu | `sudo apt install pcscd libusb-dev` |
| Fedora / RHEL | `sudo dnf install pcsc-lite` |

See [`pypassport/README.md`](./pypassport/README.md) for full reader driver installation instructions (ACR122U etc.).

---

## Running the GUI

After installing both packages:

```bash
epassportviewer            # if installed as a script
# or
python -m epassportviewer  # run as a module
```

---

## Running tests

```bash
# From the repo root (after installing pytest)
pip install pytest
pytest pypassport/tests/
```

No automated test suite exists yet for `ePassportViewer` — manual testing is required.

---

## Development notes

* Each subproject has its own `pyproject.toml` and can be developed, released, and versioned independently.
* `pypassport` does **not** depend on `ePassportViewer`.
* `ePassportViewer` depends on `pypassport` and re-uses it as a library — no code is vendored or duplicated.
* Both packages use the `src/` layout for clean package discovery.
