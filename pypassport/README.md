# pypassport

Python library for reading, parsing, and researching electronic passports
(ePassports / eMRTDs) that conform to **ICAO Doc 9303**. The parser,
passive-authentication, report, and APDU-mutation generation modules can be
used offline; talking to a physical passport uses the optional `reader` extra
and a PC/SC smart card reader.

Developed by the Information Security Group (ISG) at UCLouvain. For the academic background, see: [A Survey of Security and Privacy Issues in ePassports](https://www.researchgate.net/publication/286047538_A_Survey_of_Security_and_Privacy_Issues_in_ePassports).

A desktop GUI built on top of this library is available in the same repository: [`epassportviewer/`](../epassportviewer/).

---

## What it does

### Protocol support

`pypassport` implements the LDS and the access-control / authentication flows
used by this project:

| Protocol | Standard | Description |
|----------|----------|-------------|
| **BAC** | ICAO 9303 Part 11 | Basic Access Control — derives 3DES session keys from MRZ data; provides mutual authentication and establishes encrypted Secure Messaging |
| **PACE** | ICAO 9303 Part 11 | Password Authenticated Connection Establishment — ECDH Generic Mapping with Brainpool P-256-r1 and AES-128/192/256 session keys |
| **Secure Messaging** | ISO 9797 / ICAO 9303 | Encrypts and MACs every APDU after BAC/PACE using 3DES or AES session keys and a Send Sequence Counter |
| **Passive Authentication** | ICAO 9303 Part 11 | Verifies the Document Security Object (EF.SOD) against a Document Signer Certificate (DSC) and its issuing Country Signing CA (CSCA); validates data group hashes |
| **Active Authentication** | ICAO 9303 Part 11 | Detects chip cloning — the chip signs a random challenge with the RSA or ECDSA private key whose public counterpart is stored in DG15 |
| **Chip Authentication** | BSI TR-03110 / EAC | CA v1/v2 with DH/ECDH and 3DES/AES re-keys Secure Messaging and verifies chip-key possession |
| **Terminal Authentication** | BSI TR-03110 / EAC | Validates CVC paths/CHAT rights and authenticates inspection systems for protected biometrics |

PACE supports DH/ECDH Generic and Integrated Mapping, ECDH Chip Authentication
Mapping, 3DES and AES-128/192/256, standardized parameters, issuer-supplied
explicit parameters, and MRZ/CAN/PIN/PUK password references. The
EF.CardSecurity evidence required to finish CAM must subsequently complete
Passive Authentication.

### Logical Data Structure (LDS)

The library has parser classes for the LDS files below. Whether a physical
chip returns a file depends on the document's access controls; DG3 and DG4, in
particular, are usually EAC/Terminal Authentication protected.

| Tag | Name | Content |
|-----|------|---------|
| EF.COM | Common | LDS version and list of present data groups |
| DG1 | Machine Readable Zone | Printed MRZ text fields (document number, nationality, name, etc.) |
| DG2 | Facial image | CBEFF-wrapped JPEG or JPEG2000 image (ISO 19794-5) |
| DG3 | Fingerprints | Finger biometric templates (typically EAC-protected) |
| DG4 | Iris | Iris biometric templates (typically EAC-protected) |
| DG5 | Displayed portrait | Displayed portrait image |
| DG6 | Reserved | Reserved for future use |
| DG7 | Signature / usual mark | JPEG of the holder's signature |
| DG8–DG10 | Data features | Optional machine-assisted security data |
| DG11 | Additional personal details | Full name, other names, personal number |
| DG12 | Additional document details | Issuing authority, date of issue |
| DG13 | Optional details | Country-specific optional details |
| DG14 | Security infos | Active / Chip / Terminal Authentication and EAC metadata |
| DG15 | Active Authentication public key | RSA or ECDSA public key used for AA |
| DG16 | Persons to notify | Optional next-of-kin information |
| EF.SOD | Security Data Object | PKCS#7-wrapped signed hash manifest |
| EF.CardAccess | Access-control infos | Pre-authentication PACE SecurityInfos |

### MRZ parsing

The high-level DG1 parser handles full TD1, TD2, and TD3 MRZ contents. The
`MRZ` helper used for BAC/PACE key derivation accepts either a
`(document_number, date_of_birth, date_of_expiry)` tuple or the legacy
44-/60-character key-material strings used by the existing API.

- Check digit validation (weighting table `[7, 3, 1]`)
- Extraction of document number, date of birth, and expiry date for access-control key derivation
- Used by BAC and MRZ-based PACE for key derivation

### Security research attacks

| Attack | Description |
|--------|-------------|
| **Brute Force** | Online and offline BAC brute force — iterates MRZ combinations over document number, date-of-birth, and expiry-date ranges |
| **MAC Traceability** | Chothia & Smirnov (University of Birmingham) — a saved BAC message/MAC pair can identify a specific passport across interactions, breaking unlinkability |
| **AA Traceability** | RSA modulus leakage during Active Authentication allows passive tracking of a chip across multiple reader sessions |
| **Sign-Everything** | Misuse of the Internal Authentication command to sign arbitrary 8-byte messages using the AA private key |

The legacy active chip fingerprint workflow (including non-standard error
response collection) lives in `pypassport.fingerprint.Fingerprint` — see
*Fingerprint analysis* below.

### Security reports and APDU fuzzing

The current GUI security workbench is backed by two library modules that can
also be used directly:

- `pypassport.security_audit.build_security_report(...)` builds a side-effect
  free report from captured LDS files, access-control metadata, integrity
  results, and live-check results.
- `pypassport.fuzzing` generates bounded deterministic APDU mutation campaigns,
  executes them over an existing `ISO7816` channel, and summarizes response
  status / timing clusters.

### Fingerprint analysis

The legacy `Fingerprint` class runs an active, BAC-oriented analysis of a
passport chip and reports:

- ATR, UID, data group inventory and sizes
- BAC status, generation heuristic, delay-security implementation
- CSCA/DSC certificate chain verification when a CSCA directory is supplied
- Active Authentication result and public key
- Vulnerability indicators: MAC traceability, AA-before-BAC, block-after-fail

It resets the card and drives multiple live probes, so use it only when the
caller can give it ownership of the session. For a report from already
captured files without additional card traffic, use `build_security_report`.

---

## Installation

### Requirements

A PC/SC service and NFC reader driver must be installed before the library can connect to a physical passport. See [System dependencies](#system-dependencies) below.

### Install the library

From the monorepo root:

```bash
python -m venv .venv
source .venv/bin/activate   # Linux / macOS
# .venv\Scripts\activate    # Windows

python -m pip install --upgrade pip
# Offline parsing / protocol code only
python -m pip install -e ./pypassport

# Add this extra when talking to a physical PC/SC reader
python -m pip install -e "./pypassport[reader]"
```

Verify:

```bash
python -c "import pypassport; print('pypassport installed OK')"
```

From the monorepo root, `uv sync --package pypassport` and
`uv sync --package pypassport --extra reader` are the equivalent `uv`
commands.

---

## Usage

### Connecting to a reader

```python
from pypassport import reader

# List all available PC/SC readers
readers = reader.list_readers()
print(readers)

# Get a connection for the first reader
r = reader.get_reader()
if r is None:
    raise RuntimeError("No PC/SC reader found")
```

### Reading data groups

```python
from pypassport import EPassport

# MRZ fields: (document number, date of birth YYMMDD, expiry date YYMMDD)
mrz = ("EP123456", "850101", "260101")
ep = EPassport(r, mrz, select_aid=False)
ep.open(access_control="auto")

# Data groups are read lazily on first access and cached.
dg1 = ep["DG1"]  # parsed MRZ data
dg2 = ep["DG2"]  # parsed DG2 biometric container
com = ep["COM"]  # parsed EF.COM object
present_dgs = ep.read_com()  # ["DG1", "DG2", ...]
sod = ep["SOD"]

# Read all data groups declared in EF.COM
ep.read_data_groups()
```

### Automatic PACE/BAC selection

Some passports refuse BAC and require PACE. `ep.open()` inspects
`EF.CardAccess` to discover what the chip advertises, runs a supported
mechanism, and then selects the eMRTD application. BAC-only chips continue to
work without any extra configuration.

```python
from pypassport import EPassport

mrz = ("EP123456", "850101", "260101")
ep = EPassport(r, mrz, select_aid=False)

# "auto" (default): read EF.CardAccess, use an implemented PACE profile if
# advertised, else BAC.
# "pace": require an implemented PACE profile; raise if EF.CardAccess is
# missing or unsupported.
# "bac":  force BAC, never read EF.CardAccess.
ep.open(access_control="auto")

print(ep.access_control)   # <NegotiationResult mechanism=PACE ...> or BAC
dg1 = ep["DG1"]
dg2 = ep["DG2"]
```

If the chip rejects BAC with status word `6A88` (*referenced data not
found*), pypassport raises a helpful error suggesting to retry with
`access_control="auto"` or `access_control="pace"` — that status word
typically indicates the document requires PACE rather than BAC.

### Extracting the facial image

```python
faces = ep.get_faces()
with open("photo.jpg", "wb") as f:
    f.write(faces[0])
```

### Active Authentication

```python
result = ep.do_active_authentication()
print("AA passed:", result)           # True / False

pubkey = ep.get_public_key()          # RSA or ECDSA public key (PEM)
```

### Passive Authentication

Passive Authentication requires a directory of trusted CSCA certificates.
`TrustStore` loads `.cer`, `.crt`, `.pem`, `.der`, and ICAO Master List `.ml`
files from that directory. Master Lists require explicit MLSC trust anchors;
the strict path also processes link certificates, CRLs, and signed Deviation
Lists.
When an issuing state has published its CSCA through ICAO, it is available in
the [ICAO Master List](https://www.icao.int/icao-pkd/icao-master-list);
otherwise use that state's national PKI.

```python
ep.csca_directory = "/path/to/csca/certs"

sod_ok   = ep.do_verify_sod_certificate()   # True if SOD signature and DSC -> CSCA chain verify
dg_ok    = ep.do_verify_dg_integrity()      # dict of DG name -> True/False/None
cert_pem = ep.get_certificate()             # Document Signer Certificate (PEM)
```

### PACE

PACE needs no separate call: `ep.open()` reads `EF.CardAccess`, selects the
strongest locally supported DH/ECDH GM/IM/CAM AES/3DES profile, and enters BAC
only for a BAC-only document unless downgrade was explicitly permitted. To
require PACE explicitly:

```python
ep.open(access_control="pace")   # raises if the chip can't do implemented PACE
print(ep.access_control)         # <NegotiationResult mechanism=PACE ...>
```

### Dumping the passport to disk

```python
from pathlib import Path

dump_dir = Path("/tmp/passport_dump")
dump_dir.mkdir(parents=True, exist_ok=True)
ep.dump(directory=dump_dir)
# Writes COM.bin, DG1.bin, SOD.bin, etc. plus face0.jpg, signature0.jpg,
# DG15PubKey.pk and DocumentSigner.cer
```

### MRZ parsing standalone

```python
from pypassport.doc9303.mrz import MRZ

mrz = MRZ("L898902C36UTO7408122F1204159ZE184226B<<<<<10")
mrz.check_mrz()            # True

print(mrz.doc_number)      # ('L898902C3', '6') — value + check digit
print(mrz.date_of_birth)   # ('740812', '2')
print(mrz.date_of_expiry)  # ('120415', '9')
```

### BAC attack — brute force

```python
from pypassport.attacks.brute_force import BruteForce

bf = BruteForce(ep.iso7816)
bf.set_id(low="AB1234560", high="AB1234590")
bf.set_dob(low="800101", high="850101")
bf.set_exp_date(low="250101", high="260101")

if bf.check()[0]:
    mrz = bf.exploit()         # online: tries each MRZ against the live chip
    print("Found MRZ:", mrz)
```

### MAC traceability attack

```python
from pypassport.attacks.mac_traceability import MacTraceability

attack = MacTraceability(ep.iso7816, mrz="L898902C36UTO7408122F1204159ZE184226B<<<<<10")
(vulnerable, comment) = attack.is_vulnerable()
print(vulnerable, comment)

# Save a fingerprint pair for later identification
path = attack.save_pair(path="/tmp", filename="target-pair")

# Re-identify the passport at a later point
attack.check_from_file(path)
```

---

## Architecture

```
EPassport (dict)
 ├── ISO7816          — APDU transport layer (ISO 7816-4 commands)
 │    └── SecureMessaging — protects APDUs after BAC/PACE (ISO 9797 padding + 3DES/AES)
 ├── BAC              — derives Kenc/Kmac from MRZ; runs mutual authentication
 ├── PACE             — DH/ECDH GM, IM and CAM with 3DES/AES
 ├── Conformance      — redacted TR-03105 live profile evidence
 ├── ActiveAuthentication  — sends challenge, verifies RSA or ECDSA signature against DG15
 ├── PassiveAuthentication — verifies EF.SOD, certificate chain, DG hashes
 └── MRZ              — validates access-control MRZ key material

pypassport.attacks/
 ├── BruteForce       — iterates MRZ space against BAC
 ├── MacTraceability  — Chothia & Smirnov traceability via MAC pair
 ├── AATraceability   — RSA modulus traceability via AA
 └── SignEverything   — arbitrary signing via AA command abuse

pypassport.fingerprint.Fingerprint — legacy active chip analysis (generation
                                     heuristic, vulnerability probes,
                                     error-response collection)

pypassport.security_audit — side-effect-free report generation from captures
pypassport.fuzzing        — deterministic APDU mutation campaigns
```

---

## System dependencies

### PC/SC service

```bash
# Debian / Ubuntu
sudo apt install pcscd pcsc-tools libccid

# Arch / Manjaro
sudo pacman -S pcsclite ccid

# Fedora
sudo dnf install pcsc-lite pcsc-lite-ccid
```

If `pyscard` has to be built from source, also install `libpcsclite-dev` on
Debian / Ubuntu or `pcsc-lite-devel` on Fedora; packaged wheels do not need the
headers.

### ACR122U on Linux

If an ACR122U is visible on USB but `pcsc_scan` reports
`LIBUSB_ERROR_BUSY`, the kernel NFC modules may have claimed it before
`pcscd`. Blacklist those modules instead of deleting kernel files:

```bash
sudo tee /etc/modprobe.d/blacklist-nfc.conf <<EOF
blacklist pn533_usb
blacklist pn533
blacklist nfc
EOF

sudo modprobe -r pn533_usb pn533 nfc
sudo systemctl restart pcscd
pcsc_scan
```

Install the reader vendor's CCID driver if the generic CCID package does not
recognize the device.

### Troubleshooting

**"Failure to list readers: Service not Available."**

```bash
sudo systemctl restart pcscd
```

**No card detected / empty reader list**

- Ensure the passport is placed flat on the reader surface.
- Verify `pcscd` is running: `systemctl status pcscd`.
- Check the reader driver and device permissions if the daemon sees the reader
  only as root.

**BAC fails with `6A88` (referenced data not found)**

The chip does not accept BAC and probably requires PACE. Use the
automatic negotiator, which reads `EF.CardAccess` first:

```python
ep = EPassport(r, mrz, select_aid=False)
ep.open(access_control="auto")
```

**`6982` (security status not satisfied)**

Secure messaging has not been established yet. Call `ep.open(...)` (or
the legacy `ep.do_basic_access_control()`) before reading data groups.

**`6A82` (file/application not found)**

The selected AID or FID does not exist on the chip. For `EF.CardAccess`,
this just means the chip is BAC-only — the automatic negotiator will
fall back to BAC. For the eMRTD AID, it means the document is not an
ICAO 9303 ePassport.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pycryptodome` | ≥ 3.20 | 3DES and AES for BAC / PACE / Secure Messaging; SHA-1/SHA-256 |
| `pyasn1` | ≥ 0.6 | ASN.1 / DER parsing for certificates and the SOD |
| `pyasn1-modules` | ≥ 0.4 | X.509 / CMS (PKCS#7) structures for the EF.SOD and certificate chain |
| `pyscard` | ≥ 2.0.9 | Optional `reader` extra for PC/SC smart card access |
| `ecdsa` | ≥ 0.19 | ECDSA for Active Authentication and PACE |

---

## Standards reference

| Standard | Used for |
|----------|----------|
| ICAO Doc 9303 Part 3 | MRZ format (TD1, TD2, TD3) |
| ICAO Doc 9303 Part 10 | Logical Data Structure (LDS), Data Group definitions |
| ICAO Doc 9303 Part 11 | BAC, PACE, Secure Messaging, Passive Authentication, Active Authentication |
| ISO/IEC 7816-4 | APDU command/response structure (CLA, INS, P1, P2, Lc, Data, Le) |
| ISO/IEC 9797-1 | Message Authentication Code algorithms and padding |
| ISO/IEC 19794-5 | Facial biometric image format (CBEFF header, JPEG, JPEG2000) |
| RFC 5652 | Cryptographic Message Syntax (CMS / PKCS#7) for EF.SOD |
| X.509 | Certificate format for DSC and CSCA chain |
