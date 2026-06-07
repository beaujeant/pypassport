# pypassport

Python library for reading, parsing, and researching electronic passports (ePassports / eMRTDs) that conform to **ICAO Doc 9303**. Communicates with the passport chip over RFID/NFC via a PC/SC smart card reader.

Developed by the Information Security Group (ISG) at UCLouvain. For the academic background, see: [A Survey of Security and Privacy Issues in ePassports](https://www.researchgate.net/publication/286047538_A_Survey_of_Security_and_Privacy_Issues_in_ePassports).

A desktop GUI built on top of this library is available in the same repository: [`ePassportViewer/`](../ePassportViewer/).

---

## What it does

### Protocol support

`pypassport` implements the full ICAO Doc 9303 protocol stack:

| Protocol | Standard | Description |
|----------|----------|-------------|
| **BAC** | ICAO 9303 Part 11 | Basic Access Control — derives 3DES session keys from MRZ data; provides mutual authentication and establishes encrypted Secure Messaging |
| **PACE** | ICAO 9303 Part 11 | Password Authenticated Connection Establishment — ECDH key agreement over Brainpool curves with AES; the modern replacement for BAC |
| **Secure Messaging** | ISO 9797 / ICAO 9303 | Encrypts and MACs every APDU after BAC/PACE using 3DES or AES session keys and a Send Sequence Counter |
| **Passive Authentication** | ICAO 9303 Part 11 | Verifies the Document Security Object (EF.SOD) against a Document Signer Certificate (DSC) and its issuing Country Signing CA (CSCA); validates data group hashes |
| **Active Authentication** | ICAO 9303 Part 11 | Detects chip cloning — the chip signs a random challenge with the RSA private key whose public counterpart is stored in DG15 |

### Logical Data Structure (LDS)

Reads all data groups defined in ICAO 9303 Part 10:

| Tag | Name | Content |
|-----|------|---------|
| EF.COM | Common | LDS version and list of present data groups |
| DG1 | Machine Readable Zone | Printed MRZ text fields (document number, nationality, name, etc.) |
| DG2 | Facial image | CBEFF-wrapped JPEG or JPEG2000 image (ISO 19794-5) |
| DG3–DG5 | Fingerprints / iris | Biometric data (typically access-controlled via EAC) |
| DG7 | Signature / usual mark | JPEG of the holder's signature |
| DG11 | Additional personal details | Full name, other names, personal number |
| DG12 | Additional document details | Issuing authority, date of issue |
| DG14 | Security infos | CardAccess data (PACE parameters, EAC indicators) |
| DG15 | Active Authentication public key | RSA or ECDSA public key used for AA |
| DG16 | Persons to notify | Optional next-of-kin information |
| EF.SOD | Security Data Object | PKCS#7-wrapped signed hash manifest |

### MRZ parsing

Parses and validates Machine Readable Zones for TD1 and TD2 document formats per ICAO 9303 Part 3:

- Check digit validation (weighting table `[7, 3, 1]`)
- Extraction of document number, nationality, date of birth, expiry date, personal number
- Used by BAC for key derivation

### Security research attacks

| Attack | Description |
|--------|-------------|
| **Brute Force** | Online and offline BAC brute force — iterates MRZ combinations over document number, date-of-birth, and expiry-date ranges |
| **MAC Traceability** | Chothia & Smirnov (University of Birmingham) — a saved BAC message/MAC pair can identify a specific passport across interactions, breaking unlinkability |
| **AA Traceability** | RSA modulus leakage during Active Authentication allows passive tracking of a chip across multiple reader sessions |
| **Error Fingerprinting** | Non-standard error responses to probe APDUs reveal the chip manufacturer and issuing country without authentication |
| **Sign-Everything** | Misuse of the Internal Authentication command to sign arbitrary 8-byte messages using the AA private key |

### Fingerprint analysis

The `Fingerprint` class runs a full automated analysis of a passport chip and reports:

- ATR, UID, data group inventory and sizes
- BAC status, Secure Messaging cipher, delay-security implementation
- CSCA/DSC certificate chain verification
- Active Authentication result and public key
- Vulnerability indicators: MAC traceability, AA-before-BAC, block-after-fail

---

## Installation

### Requirements

A PC/SC service and NFC reader driver must be installed before the library can connect to a physical passport. See [System dependencies](#system-dependencies) below.

### Install the library

```bash
python -m venv .venv
source .venv/bin/activate   # Linux / macOS

pip install --upgrade pip
pip install -e ./pypassport
```

Verify:

```bash
python -c "import pypassport; print('pypassport installed OK')"
```

---

## Usage

### Connecting to a reader

```python
from pypassport import reader

# List all available PC/SC readers
readers = reader.listReaders()
print(readers)

# Connect to the first reader
r = reader.getReader()
r.connect()
```

### Reading data groups

```python
from pypassport.epassport import EPassport

# MRZ fields: (document number, date of birth YYMMDD, expiry date YYMMDD)
ep = EPassport(r, ("EP123456", "850101", "260101"))

# Data groups are read lazily on first access and cached.
# BAC is triggered automatically if the chip requires it.
dg1 = ep["DG1"]     # MRZ data
dg2 = ep["DG2"]     # facial image
com  = ep["Common"] # list of present data groups
sod  = ep["SecurityData"]

# Read all data groups declared in EF.COM
ep.readDataGroups()
```

### Automatic PACE/BAC selection

Modern (post-2024) passports may refuse BAC and require PACE. `ep.open()`
inspects `EF.CardAccess` to discover what the chip advertises, runs the
appropriate mechanism, and then selects the eMRTD application. It is
backward compatible: legacy BAC-only chips continue to work without any
extra configuration.

```python
from pypassport import PassportReader   # alias for EPassport

mrz = ("EP123456", "850101", "260101")
ep = PassportReader(r, mrz, select_aid=False)

# "auto" (default): read EF.CardAccess, use PACE if advertised, else BAC.
# "pace": require PACE; raise if EF.CardAccess is missing or unsupported.
# "bac":  force BAC, never read EF.CardAccess.
ep.open(access_control="auto")

print(ep.accessControl)   # NegotiationResult(mechanism="PACE"|"BAC", ...)
dg1 = ep["DG1"]
dg2 = ep["DG2"]
```

If the chip rejects BAC with status word `6A88` (*referenced data not
found*), pypassport raises a helpful error suggesting to retry with
`access_control="auto"` or `access_control="pace"` — that status word
typically indicates the document requires PACE rather than BAC.

### Extracting the facial image

```python
faces = ep.getFaces()
with open("photo.jpg", "wb") as f:
    f.write(faces[0])
```

### Active Authentication

```python
result = ep.doActiveAuthentication()
print("AA passed:", result)           # True / False

pubkey = ep.getPublicKey()            # RSA public key text
```

### Passive Authentication

Passive Authentication requires a directory of CSCA certificates (one PEM file per country). ICAO publishes the [CSCA Master List](https://www.icao.int/Security/FAL/PKD/Pages/ICAO-Master-List.aspx).

```python
ep.setCSCADirectory("/path/to/csca/certs", hash=True)

sod_ok   = ep.doVerifySODCertificate()   # True if DS cert chains to a CSCA
dg_ok    = ep.doVerifyDGIntegrity()      # dict of DG tag → True/False
cert_pem = ep.getCertificate()           # Document Signer Certificate (PEM)
```

### PACE

```python
# DG14 must be read first to obtain the PACE parameters
dg14 = ep["DG14"]
ep.doPACE()
```

### Dumping the passport to disk

```python
ep.dump(directory="/tmp/passport_dump", format="GRT")
# Writes individual DG files plus face.jpg, signature.jpg,
# DG15PubKey.pk and DocumentSigner.cer
```

### MRZ parsing standalone

```python
from pypassport.doc9303.mrz import MRZ

mrz = MRZ("EP123456<3BEL8501011M2601017<<<<<<<<<<<<<<04")
mrz.checkMRZ()            # True

print(mrz.docNumber)      # ('EP123456', '3')   — value + check digit
print(mrz.dateOfBirth)    # ('850101', '1')
print(mrz.dateOfExpiry)   # ('260101', '7')
```

### BAC attack — brute force

```python
from pypassport.attacks.bruteForce import BruteForce

bf = BruteForce(ep.iso7816)
bf.setID(low="AB1234560", high="AB1234590")
bf.setDOB(low="800101", high="850101")
bf.setExpDate(low="250101", high="260101")

if bf.check()[0]:
    mrz = bf.exploit()         # online: tries each MRZ against the live chip
    print("Found MRZ:", mrz)
```

### MAC traceability attack

```python
from pypassport.attacks.macTraceability import MacTraceability

attack = MacTraceability(ep.iso7816, mrz="EP123456<3BEL8501011M2601017<<<<<<<<<<<<<<04")
(vulnerable, comment) = attack.isVulnerable()
print(vulnerable, comment)

# Save a fingerprint pair for later identification
path = attack.savePair(path="/tmp", filename="target-pair")

# Re-identify the passport at a later point
attack.checkFromFile(path)
```

---

## Architecture

```
EPassport (dict)
 ├── ISO7816          — APDU transport layer (ISO 7816-4 commands)
 │    └── SecureMessaging — protects APDUs after BAC/PACE (ISO 9797 padding + 3DES/AES)
 ├── BAC              — derives Kenc/Kmac from MRZ; runs mutual authentication
 ├── PACE             — ECDH key agreement (Brainpool curves)
 ├── ActiveAuthentication  — sends challenge, verifies RSA signature against DG15
 ├── PassiveAuthentication — verifies EF.SOD, certificate chain, DG hashes
 └── MRZ              — parses and validates the Machine Readable Zone

pypassport.attacks/
 ├── BruteForce       — iterates MRZ space against BAC
 ├── MacTraceability  — Chothia & Smirnov traceability via MAC pair
 ├── AATraceability   — RSA modulus traceability via AA
 ├── ErrorFingerprinting — identifies chip by error response patterns
 └── SignEverything   — arbitrary signing via AA command abuse
```

---

## System dependencies

### PC/SC service

```bash
# Debian / Ubuntu
sudo apt install pcscd libusb-dev

# Arch / Manjaro
sudo pacman -S pcsclite

# Fedora / RHEL
sudo dnf install pcsc-lite
```

### ACR122U — driver installation (Ubuntu example)

1. Unplug the reader.
2. Download and install the ACS unified driver:

```bash
cd /tmp
wget https://www.acs.com.hk/download-driver-unified/10312/ACS-Unified-PKG-Lnx-116-P.zip
unzip ACS-Unified-PKG-Lnx-116-P.zip
cd ACS-Unified-PKG-Lnx-116-P/acsccid_linux_bin-1.1.6/ubuntu/bionic/
sudo dpkg -i libacsccid1_1.1.6-1~ubuntu18.04.1_amd64.deb
```

3. Remove the conflicting `pn533` kernel module (if present):

```bash
sudo rm -r /lib/modules/*/kernel/drivers/nfc/pn533
```

4. Test the reader:

```bash
sudo service pcscd stop
sudo pcscd -f -d     # place passport on reader — you should see ATR output
```

### Troubleshooting

**"Failure to list readers: Service not Available."**

```bash
sudo service pcscd restart
```

**No card detected / empty reader list**

- Ensure the passport is placed flat on the reader surface.
- Try `sudo` if your user is not in the `pcscd` or `scard` group.
- Verify `pcscd` is running: `sudo service pcscd status`.

**BAC fails with `6A88` (referenced data not found)**

The chip does not accept BAC and probably requires PACE. Use the
automatic negotiator, which reads `EF.CardAccess` first:

```python
ep = PassportReader(r, mrz, select_aid=False)
ep.open(access_control="auto")
```

**`6982` (security status not satisfied)**

Secure messaging has not been established yet. Call `ep.open(...)` (or
the legacy `ep.doBasicAccessControl()`) before reading data groups.

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
| `pyscard` | ≥ 2.0.9 | PC/SC smart card reader interface |
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
