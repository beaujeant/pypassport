# pypassport

Python library for communicating with electronic passports (ePassports / ICAO Doc 9303) over RFID/NFC using a PC/SC smart card reader.

Developed by the Information Security Group (ISG) of the University of Louvain (UCL). For background, see the ACM publication: [A Survey of Security and Privacy Issues in ePassports](https://www.researchgate.net/publication/286047538_A_Survey_of_Security_and_Privacy_Issues_in_ePassports).

A desktop GUI built on top of this library is available in the same repository: [`ePassportViewer/`](../ePassportViewer/).

---

## What it does

`pypassport` implements the core ICAO Doc 9303 protocols:

* **BAC** — Basic Access Control (mutual authentication using MRZ data)
* **PACE** — Password Authenticated Connection Establishment
* **Passive Authentication** — verifies the Document Security Object (SOD)
* **Active Authentication** — detects cloning vulnerability
* **Data Group reading** — DG1 (MRZ), DG2 (face image), DG14, DG15, and more
* **Attacks** — MAC Traceability, Error Fingerprinting, Brute Force, AA Sign-Everything

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

## Minimal usage example

```python
from pypassport import reader
from pypassport.epassport import EPassport

# Connect to the first available reader
r = reader.getReader()
r.connect()

# MRZ line 2 data: (document number, date of birth YYMMDD, expiry date YYMMDD)
ep = EPassport(r, ("EP123456", "850101", "260101"))

# Read Data Group 1 (MRZ data)
dg1 = ep["DG1"]
print(dg1)

# Read Data Group 2 (facial image) and save it
dg2 = ep["DG2"]
image_bytes = dg2["7F61"][0]["7F60"]["5F2E"]
with open("photo.jpg", "wb") as f:
    f.write(image_bytes)
```

---

## System dependencies

### PC/SC service

```bash
# Debian / Ubuntu
sudo apt install pcscd libusb-dev
```

### ACR122U driver (example for Ubuntu 18.04 amd64)

1. Unplug the reader.
2. Download and install the unified driver from ACS:

```bash
cd /tmp
wget https://www.acs.com.hk/download-driver-unified/10312/ACS-Unified-PKG-Lnx-116-P.zip
unzip ACS-Unified-PKG-Lnx-116-P.zip
cd ACS-Unified-PKG-Lnx-116-P/acsccid_linux_bin-1.1.6/ubuntu/bionic/
sudo dpkg -i libacsccid1_1.1.6-1~ubuntu18.04.1_amd64.deb
```

3. Unload the conflicting `pn533` kernel module:

```bash
sudo rm -r /lib/modules/*/kernel/drivers/nfc/pn533
```

4. Test the reader:

```bash
sudo service pcscd stop
sudo pcscd -f -d
# Place passport on reader — you should see ATR output
```

### Troubleshooting

**"Failure to list readers: Service not Available."**

```bash
sudo service pcscd restart
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `pycryptodome` | 3DES, AES, SHA — used for BAC/SM |
| `pyasn1` | ASN.1 parsing for certificates |
| `pyscard` | PC/SC reader interface |
| `ecdsa` | ECDSA for Active Authentication |
