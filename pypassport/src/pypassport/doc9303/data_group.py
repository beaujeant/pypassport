import os
import logging
import string

from pypassport.iso7816 import ISO7816Exception
from pypassport.utils import toHexString, toBytes, parseTLV
from pypassport.asn1 import asn1Length
from pypassport.iso19794 import BIOMETRIC_PARSERS
from pypassport.doc9303 import converter

# Reference: https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf

# DOC9303-2 pg III-38


tagToName = {
    "02" : "Integer",
    "5C" : "Tag list",

    # DataGroup
    "60" : "Common data elements",
    "61" : "Template for MRZ data group",
    "63" : "Template for Finger biometric data group",
    "65" : "Template for digitized facial image",
    "66" : "Reserved for Future Use",
    "67" : "Template for digitized Signature or usual mark",
    "68" : "Template for Machine Assisted Security - Encoded Data",
    "69" : "Template for Machine Assisted Security - Structure",
    "6A" : "Template for Machine Assisted Security - Substance",
    "6B" : "Template for Additional Personal Details",
    "6C" : "Template for Additional Document Details",
    "6D" : "Optional details (Country Specific)",
    "6E" : "Reserved for future use",
    "6F" : "Active Authentication Public Key Info",
    "70" : "Person to Notify",
    "75" : "Template for facial biometric data group",
    "76" : "Template for Iris (eye) biometric template",
    "77" : "Security Object (EF for security data)",

    "5F01" : "LDS Version Number",
    "5F08" : "Date of birth (truncated)",

    "5F09" : "Compressed image (ANSI/NIST-ITL 1-2000)",
    "5F0A" : "Security features - Encoded Data",
    "5F0B" : "Security features - Structure",
    "5F0C" : "Security features",
    "5F0E" : "Full name, in national characters",
    "5F0F" : "Other names",

    "5F10" : "Personal Number",
    "5F11" : "Place of birth",
    "5F12" : "Telephone",
    "5F13" : "Profession",
    "5F14" : "Title",
    "5F15" : "Personal Summary",
    "5F16" : "Proof of citizenship (10918 image)",
    "5F17" : "Other valid TD Numbers",
    "5F18" : "Custody information",
    "5F19" : "Issuing Authority",
    "5F1A" : "Other people on document",
    "5F1B" : "Endorsement/Observations",
    "5F1C" : "Tax/Exit requirements",
    "5F1D" : "Image of document front",
    "5F1E" : "Image of document rear",
    "5F1F" : "MRZ data elements",

    "5F26" : "Date of Issue",
    "5F2B" : "Date of birth (8 digit)",
    "5F2E" : "Biometric data block",

    "5F36" : "Unicode Version Level",

    "5F40" : "Compressed image template",
    "5F42" : "Address",
    "5F43" : "Compressed image template",

    "5F50" : "Date data recorded",
    "5F51" : "Name of person",
    "5F52" : "Telephone",
    "5F53" : "Address",

    "5F55" : "Date and time document personalized",
    "5F56" : "Serial number of personalization system",
    
    "7F2E" : "Biometric data block (enciphered)",
    "7F60" : "Biometric Information Template",
    "7F61" : "Biometric Information Group Template",

    "80" : "ICAO header version",
    "81" : "Biometric Type",
    "82" : "Biometric subtype",
    "83" : "Creation date and time",
    "84" : "Validity period", # (revized in nov 2008)
    "85" : "Validity period", # (since 2008)
    "86" : "Creator of biometric reference data",
    "87" : "Format Owner",
    "88" : "Format Type",
    "89" : "Context specific tags",
    "8A" : "Context specific tags",
    "8B" : "Context specific tags",
    "8C" : "Context specific tags",
    "8D" : "Context specific tags",
    "8E" : "Context specific tags",
    "8F" : "Context specific tags",

    "90" : "Enciphered hash code",

    "A0" : "Context specific constructed data objects",

    "A1" : "Repeating template, 1 occurrence Biometric header",
    "A2" : "Repeating template, 2 occurrence Biometric header",
    "A3" : "Repeating template, 3 occurrence Biometric header",
    "A4" : "Repeating template, 4 occurrence Biometric header",
    "A5" : "Repeating template, 5 occurrence Biometric header",
    "A6" : "Repeating template, 6 occurrence Biometric header",
    "A7" : "Repeating template, 7 occurrence Biometric header",
    "A8" : "Repeating template, 8 occurrence Biometric header",
    "A9" : "Repeating template, 9 occurrence Biometric header",
    "AA" : "Repeating template, 10 occurrence Biometric header",
    "AB" : "Repeating template, 11 occurrence Biometric header",
    "AC" : "Repeating template, 12 occurrence Biometric header",
    "AD" : "Repeating template, 13 occurrence Biometric header",
    "AE" : "Repeating template, 14 occurrence Biometric header",
    "AF" : "Repeating template, 15 occurrence Biometric header",

    "B0" : "Repeating template, 0 occurrence Biometric header",
    "B1" : "Repeating template, 1 occurrence Biometric header",
    "B2" : "Repeating template, 2 occurrence Biometric header",
    "B3" : "Repeating template, 3 occurrence Biometric header",
    "B4" : "Repeating template, 4 occurrence Biometric header",
    "B5" : "Repeating template, 5 occurrence Biometric header",
    "B6" : "Repeating template, 6 occurrence Biometric header",
    "B7" : "Repeating template, 7 occurrence Biometric header",
    "B8" : "Repeating template, 8 occurrence Biometric header",
    "B9" : "Repeating template, 9 occurrence Biometric header",
    "BA" : "Repeating template, 10 occurrence Biometric header",
    "BB" : "Repeating template, 11 occurrence Biometric header",
    "BC" : "Repeating template, 12 occurrence Biometric header",
    "BD" : "Repeating template, 13 occurrence Biometric header",
    "BE" : "Repeating template, 14 occurrence Biometric header",
    "BF" : "Repeating template, 15 occurrence Biometric header",

    # DOC9303-2 pg III-40
    "53" : "Optional Data",
    "59" : "Date of Expiry or valid Until Date",
    "02" : "Document Number",

    "5F02" : "Check digit - Optional data (ID-3 only)",
    "5F03" : "Document Type",
    "5F04" : "Check digit - Doc Number",
    "5F05" : "Check digit - DOB",
    "5F06" : "Expiry date",
    "5F07" : "Composite",

    "5F20" : "Issuing State or Organization",
    "5F2B" : "Date of birth",
    "5F2C" : "Nationality",

    "5F35" : "Sex",
    "5F57" : "Date of birth (6 digit)",

    # From DG1 (information tags)
    "5F28" : "Issuing State or Organization",
    "5F5B" : "Name of Holder", # version 2006
    "5B" : "Name of Holder",   # version 2008
    "5A" : "Document Number",

    # DOC9303-2 pg III-40
    "5F44" : "Country of entry/exit",
    "5F45" : "Date of entry/exit",
    "5F46" : "Port of entry/exit",
    "5F47" : "Entry/Exit indicator",
    "5F48" : "Length of stay",
    "5F49" : "Category (classification)",
    "5F4A" : "Inspector reference",
    "5F4B" : "Entry/Exit indicator",
    "71" : "Template for Electronic Visas",
    "72" : "Template for Border Crossing Schemes",
    "73" : "Template for Travel Record Data Group"
}

def readElementaryFile(tag, iso7816, maxSize=0xDF):
    try:
        tag = converter.toTAG(tag)
        logging.info(f"Reading {tag}...")
        offset = 0

        iso7816.selectElementaryFile(converter.toFID(tag))

        # Read DG header (to know the body size)
        headerRaw = iso7816.readBinary(offset, 4)
        header = ElementaryFileHeader(headerRaw)
        if(header.tag != tag):
            raise ElementaryFileException(f"Wrong AID: {header.tag} instead of " + tag)

        # Read the DG body
        offset += header.headerSize
        logging.debug(f"Read EF body")
        body = b""
        remaining = header.bodySize

        while remaining:
            toRead = min(remaining, maxSize)
            body += iso7816.readBinary(offset, toRead)
            remaining -= toRead
            offset += toRead

        if header.bodySize != len(body):
            raise Exception("The file is not entirely read: expected: " + str(header.bodySize) + " read: " + str(len(body)))

        # Creating the DG
        file = header.raw + body
        class_name = converter.toClass(tag)
        if class_name not in _CLASS_MAP:
            raise ElementaryFileException(f"Unknown class for tag {tag}: {class_name}")
        return _CLASS_MAP[class_name](file=file)
    except ISO7816Exception as e:
        raise e


class ElementaryFileException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class ElementaryFileHeader():
    def __init__(self, header):
        if isinstance(header, list):
            header = bytes(header)
        if isinstance(header, str):
            header = toBytes(header)
        if not isinstance(header, bytes):
            raise ElementaryFileException(f"ElementaryFileHeader: expected bytes, got {type(header).__name__}")
        self.tag = toHexString(header[0])
        (self.bodySize, lenSize) = asn1Length(header[1:])
        self.headerSize = lenSize + 1
        self.raw = header[:self.headerSize]


class ElementaryFile(dict):
    def __init__(self, tag="", header=None, body=b"", file=b""):
        self.tag = ""
        self._header = None
        self._body = b""

        if tag: self.tag = tag
        if header: self.header = header
        if body: self.body = body
        if file: self.file = file

    def _setHeader(self, header):
        if isinstance(header, ElementaryFileHeader):
            self.tag = header.tag
            self._header = header
        elif isinstance(header, str) or isinstance(header, bytes):
            self._header = ElementaryFileHeader(header)
            self.tag = self._header.tag
        else:
            logging.error("The provided header is not a ElementaryFileHeader, a str or a bytes.")
        if self.body:
            self.init_parse()

    def _getHeader(self):
        return self._header

    def _setBody(self, body):
        if isinstance(body, list):
            body = bytes(body)
        if isinstance(body, str):
            body = toBytes(body)
        if not isinstance(body, bytes):
            raise ElementaryFileException(f"ElementaryFile body: expected bytes, got {type(body).__name__}")
        self._body = body
        if self.header:
            self.init_parse()

    def _getBody(self):
        return self._body

    def _setFile(self, file):
        if isinstance(file, list):
            file = bytes(file)
        if isinstance(file, str):
            file = toBytes(file)
        if not isinstance(file, bytes):
            raise ElementaryFileException(f"ElementaryFile file: expected bytes, got {type(file).__name__}")
        self.header = file[:4]
        offset = self.header.headerSize
        self.body = file[offset:]

    def _getFile(self):
        return self._header.raw + self._body

    def _getLen(self):
        return len(self.file)

    def init_parse(self):
        #logging.debug(f"Body: {self.body}")
        if self.tag not in ["65", "67", "6F", "77"]:
            self.update(self.parse_dict(self.body))
            self.parse_map()
        else:
            self["raw"] = self.body

    def parse_dict(self, data):
        output = {}
        offset = 0
        try:
            while offset < len(data):
                tag, value, total_length = parseTLV(data[offset:])
                output[tag] = value
                offset += total_length
        except Exception as e:
            logging.error(f"An error took place while parsing the DataFile. Reason: {e} ({type(e)})")
        return output

    def parse_array(self, data):
        output = {}

        tag, value, offset = parseTLV(data)
        if tag != "02":
            raise ElementaryFileException(f"parse_array: expected tag 02, got {tag}")
        output["02"] = int.from_bytes(value, 'big')

        array = []
        for _ in range(output["02"]):
            tag, value, length = parseTLV(data[offset:])
            array.append(value)
            offset += length
        output[tag] = array

        return tag, output, offset

    def parse_map(self):
        if "5C" in self:
            map = self["5C"]
            self["5C"] = []
            index = 0
            while index < len(map):
                current = map[index]
                if (current & 0x1F) == 0x1F:  # BER-TLV multi-byte tag indicator
                    reference = [current, map[index+1]]
                    index += 1
                else:
                    reference = [current]
                self["5C"].append(toHexString(reference))
                index += 1

    def print_any(self, node, output="", level=0):
        nl = "\n"
        if isinstance(node, dict):
            for key, value in node.items():
                tab = "\t"*level
                try:
                    extra = f" ({tagToName[key]})"
                except KeyError:
                    extra = ""
                output += f"{nl}{tab}[{key}]{extra}: "
                output = self.print_any(value, output, level+1)
        if isinstance(node, list):
            index = 0
            for value in node:
                tab = "\t"*level
                output += f"{nl}{tab}[{index}]: "
                output = self.print_any(value, output, level+1)
                index += 1
        if isinstance(node, int):
            output += toHexString(node)
        if isinstance(node, bytes):
            printable = True
            for char in node:
                if chr(char) not in string.printable:
                    printable = False
                    break
            if printable:
                output += node.decode()
            else:
                output += toHexString(node)
        if isinstance(node, str):
            output += node
        return output

    def __str__(self):
        return self.print_any(self)

    header = property(_getHeader, _setHeader)
    body = property(_getBody, _setBody)
    file = property(_getFile, _setFile)
    len = property(_getLen)


class BiometricTemplates(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)

    def parse(self):
        if "7F61" not in self:
            logging.warning("BiometricTemplates: missing 7F61, storing raw body")
            self["raw"] = self.body
            return

        bitgt = self["7F61"]
        self["7F61"] = []

        try:
            tag, value, offset = parseTLV(bitgt)
            if tag != "02":
                raise ElementaryFileException(f"BiometricTemplates: expected tag 02, got {tag}")
            count = int.from_bytes(value, 'big')

            for i in range(count):
                tag, bit, bit_length = parseTLV(bitgt[offset:])
                if tag != "7F60":
                    raise ElementaryFileException(f"BiometricTemplates: expected 7F60, got {tag}")
                self["7F61"].append({"7F60": {}})

                inner_offset = 0
                # Biometric Header Template (A1) is optional per spec
                first_tag, first_val, first_len = parseTLV(bit[inner_offset:])
                if first_tag == "A1":
                    self["7F61"][i]["7F60"]["A1"] = self.parse_dict(first_val)
                    inner_offset += first_len
                    bdb_tag, bdb, _ = parseTLV(bit[inner_offset:])
                else:
                    # No BHT — first element is already the BDB
                    bdb_tag, bdb = first_tag, first_val

                if bdb_tag not in ("5F2E", "7F2E"):
                    logging.warning(f"BiometricTemplates: unexpected BDB tag {bdb_tag}, storing raw")
                    self["7F61"][i]["7F60"][bdb_tag] = bdb
                else:
                    try:
                        magic = bdb[:4]
                        analyser = BIOMETRIC_PARSERS.get(magic)
                        if analyser is None:
                            logging.warning(f"BiometricTemplates: unknown biometric magic {magic!r}, storing raw BDB")
                            self["7F61"][i]["7F60"][bdb_tag] = bdb
                        else:
                            self["7F61"][i]["7F60"]["meta"], meta_len = analyser(bdb)
                            self["7F61"][i]["7F60"][bdb_tag] = bdb[meta_len:]
                    except Exception as e:
                        logging.warning(f"BiometricTemplates: CBEFF parse failed: {e}, storing raw BDB")
                        self["7F61"][i]["7F60"][bdb_tag] = bdb

                offset += bit_length

            # Trailing data
            while offset < len(bitgt):
                tag, extra, extra_length = parseTLV(bitgt[offset:])
                self["7F61"][tag] = extra
                offset += extra_length

        except ElementaryFileException:
            raise
        except Exception as e:
            logging.warning(f"BiometricTemplates: parse error ({e}), storing raw 7F61")
            if not self["7F61"]:
                self["7F61"] = bitgt


class DisplayedImageTemplates(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
    
    def parse(self):
        tag, value, offset = self.parse_array(self.body)
        if tag not in ("5F40", "5F43"):
            raise ElementaryFileException(f"DisplayedImageTemplates: expected tag 5F40 or 5F43, got {tag}")
        self.update(value)

        # If extra data
        while offset < len(self.body):
            tag, extra, extra_length = parseTLV(self.body[offset:])
            self[tag] = extra
            offset += extra_length


class Common(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"EF.COM: parse failed ({e})")

    def parse(self):
        # 5F01: LDS Version Number (e.g. b"0107" → "1.7")
        if "5F01" in self:
            raw = self["5F01"]
            if isinstance(raw, bytes) and len(raw) >= 4:
                try:
                    self["lds_version"] = f"{int(raw[0:2])}.{int(raw[2:4])}"
                except (ValueError, TypeError):
                    self["lds_version"] = raw.decode('ascii', errors='replace')
        # 5F36: Unicode Version Level (e.g. b"040000" → "4.0.0")
        if "5F36" in self:
            raw = self["5F36"]
            if isinstance(raw, bytes) and len(raw) >= 6:
                try:
                    self["unicode_version"] = f"{int(raw[0:2])}.{int(raw[2:4])}.{int(raw[4:6])}"
                except (ValueError, TypeError):
                    self["unicode_version"] = raw.decode('ascii', errors='replace')


class SOD(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class DataGroup1(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG1: parse failed ({e}), keeping raw MRZ bytes")

    def parse(self):
        if "5F1F" not in self:
            raise ElementaryFileException("DG1: missing MRZ tag 5F1F")
        raw = self["5F1F"]
        length = len(raw)
        try:
            data = raw.decode('ascii')
        except (UnicodeDecodeError, AttributeError):
            data = raw.decode('latin-1')

        # Always preserve the raw MRZ string as a fallback
        self["5F1F"] = {"mrz": data}

        if length == 90:    # TD1: 3 lines × 30 chars
            self._parseTD1(data)
        elif length == 72:  # TD2: 2 lines × 36 chars
            self._parseTD2(data)
        elif length == 88:  # TD3 (passport): 2 lines × 44 chars
            self._parseTD3(data)
        else:
            logging.warning(f"DG1: unknown MRZ length {length}, raw MRZ stored under 'mrz'")

    def _parseTD1(self, data):
        # ICAO 9303 Part 3 — TD1 (90 chars, 3 lines of 30)
        # Line 1
        self["5F1F"]["5F03"]  = data[0:2]    # Document type
        self["5F1F"]["5F28"]  = data[2:5]    # Issuing state
        self["5F1F"]["5A"]    = data[5:14]   # Document number
        self["5F1F"]["5F04"]  = data[14:15]  # Check digit — doc number
        self["5F1F"]["53_L1"] = data[15:30]  # Optional data (line 1)
        # Line 2
        self["5F1F"]["5F57"]  = data[30:36]  # Date of birth
        self["5F1F"]["5F05"]  = data[36:37]  # Check digit — DOB
        self["5F1F"]["5F35"]  = data[37:38]  # Sex
        self["5F1F"]["59"]    = data[38:44]  # Date of expiry
        self["5F1F"]["5F06"]  = data[44:45]  # Check digit — expiry
        self["5F1F"]["5F2C"]  = data[45:48]  # Nationality
        self["5F1F"]["53"]    = data[48:59]  # Optional data (line 2)
        self["5F1F"]["5F07"]  = data[59:60]  # Composite check digit
        # Line 3
        self["5F1F"]["5B"]    = data[60:90]  # Holder name (primary<<secondary)
        self["5F1F"]["5F5B"]  = data[60:90]  # Alias for cross-TD compat

    def _parseTD2(self, data):
        # ICAO 9303 Part 3 — TD2 (72 chars, 2 lines of 36)
        # Line 1
        self["5F1F"]["5F03"] = data[0:2]    # Document type
        self["5F1F"]["5F28"] = data[2:5]    # Issuing state
        self["5F1F"]["5B"]   = data[5:36]   # Holder name
        self["5F1F"]["5F5B"] = data[5:36]   # Alias for cross-TD compat
        # Line 2
        self["5F1F"]["5A"]   = data[36:45]  # Document number
        self["5F1F"]["5F04"] = data[45:46]  # Check digit — doc number
        self["5F1F"]["5F2C"] = data[46:49]  # Nationality
        self["5F1F"]["5F57"] = data[49:55]  # Date of birth
        self["5F1F"]["5F05"] = data[55:56]  # Check digit — DOB
        self["5F1F"]["5F35"] = data[56:57]  # Sex
        self["5F1F"]["59"]   = data[57:63]  # Date of expiry
        self["5F1F"]["5F06"] = data[63:64]  # Check digit — expiry
        self["5F1F"]["53"]   = data[64:71]  # Optional data
        self["5F1F"]["5F07"] = data[71:72]  # Composite check digit

    def _parseTD3(self, data):
        # ICAO 9303 Part 3 — TD3 / passport (88 chars, 2 lines of 44)
        # Line 1
        self["5F1F"]["5F03"] = data[0:2]    # Document type
        self["5F1F"]["5F28"] = data[2:5]    # Issuing state
        self["5F1F"]["5F5B"] = data[5:44]   # Holder name (primary<<secondary)
        self["5F1F"]["5B"]   = data[5:44]   # Alias for cross-TD compat
        # Line 2
        self["5F1F"]["5A"]   = data[44:53]  # Document number
        self["5F1F"]["5F04"] = data[53:54]  # Check digit — doc number
        self["5F1F"]["5F2C"] = data[54:57]  # Nationality
        self["5F1F"]["5F57"] = data[57:63]  # Date of birth
        self["5F1F"]["5F05"] = data[63:64]  # Check digit — DOB
        self["5F1F"]["5F35"] = data[64:65]  # Sex
        self["5F1F"]["59"]   = data[65:71]  # Date of expiry
        self["5F1F"]["5F06"] = data[71:72]  # Check digit — expiry
        self["5F1F"]["53"]   = data[72:86]  # Personal number / optional data
        self["5F1F"]["5F02"] = data[86:87]  # Check digit — personal number
        self["5F1F"]["5F07"] = data[87:88]  # Composite check digit


class DataGroup2(BiometricTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()


class DataGroup3(BiometricTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()


class DataGroup4(BiometricTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()


class DataGroup5(DisplayedImageTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()


class DataGroup6(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Reserved for futur use


class DataGroup7(DisplayedImageTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()


class DataGroup8(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Proprietary usage


class DataGroup9(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Proprietary usage


class DataGroup10(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Proprietary usage


class DataGroup11(ElementaryFile):
    # Tags whose value is a counted array of repeated sub-TLV entries (ICAO 9303 Part 10 §4.7.11)
    _ARRAY_TAGS = {"5F0F", "5F17"}

    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG11: parse failed ({e}), keeping raw TLV data")

    def parse(self):
        if "5C" not in self:
            return
        for tag in self["5C"]:
            if tag not in self or tag not in self._ARRAY_TAGS:
                continue
            try:
                _, parsed, _ = self.parse_array(self[tag])
                # Replace raw bytes with the decoded list; keep count under "02"
                self[tag] = parsed
            except Exception as e:
                logging.warning(f"DG11: array parse failed for tag {tag}: {e}")


class DataGroup12(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG12: parse failed ({e}), keeping raw TLV data")

    def parse(self):
        if "5C" not in self:
            return
        # A0 wraps a counted array of 5F1A (names of other persons on the document)
        if "A0" in self["5C"] and "A0" in self:
            try:
                tag, parsed, _ = self.parse_array(self["A0"])
                self["A0"] = parsed  # {"02": count, tag: [bytes, ...]}
            except Exception as e:
                logging.warning(f"DG12: A0 array parse failed: {e}")


class DataGroup13(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Proprietary usage


class DataGroup14(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG14: SecurityInfo parse failed ({e})")

    def parse(self):
        from pypassport.doc9303.security_info import SecurityInfoParser, SecurityInfoParseError
        self["security_infos"] = SecurityInfoParser().parse(self.body)


class DataGroup15(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG15: SubjectPublicKeyInfo parse failed ({e})")

    def parse(self):
        # Body is raw DER SubjectPublicKeyInfo; parse with pyasn1 to expose
        # algorithm OID and key size without disturbing the raw body used by
        # active_authentication.py.
        from pyasn1.codec.der import decoder as asn1dec
        from pypassport.asn1 import SubjectPublicKeyInfo
        spki, _ = asn1dec.decode(self.body, asn1Spec=SubjectPublicKeyInfo())
        algo_oid = str(spki['algorithm']['algorithm'])
        self["algorithm_oid"] = algo_oid
        # Translate OID to a human-readable name when known
        try:
            from pypassport.der_object_identifier import OID
            self["algorithm"] = OID.get(algo_oid, algo_oid)
        except Exception:
            self["algorithm"] = algo_oid
        # Key length in bits (BitString length)
        key_bits = spki['subjectPublicKey']
        self["key_length_bits"] = len(key_bits)


class DataGroup16(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG16: parse failed ({e})")

    def parse(self):
        # ICAO 9303 Part 10 §4.7.16: DG16 holds a counted list of person-to-
        # notify records. 5C gives the set of tags present per person; 02 gives
        # the count. Each person is then len(5C) consecutive TLV entries.
        if "5C" not in self or "02" not in self:
            return

        count = int.from_bytes(self["02"], 'big')
        person_tags = self["5C"]  # ordered list after parse_map

        # Re-walk the raw body to find where person data begins (after 5C and 02)
        data = self.body
        offset = 0
        seen = set()
        while offset < len(data) and not {"5C", "02"}.issubset(seen):
            tag, _, length = parseTLV(data[offset:])
            seen.add(tag)
            offset += length

        persons = []
        for _ in range(count):
            person = {}
            for expected_tag in person_tags:
                if offset >= len(data):
                    break
                tag, value, length = parseTLV(data[offset:])
                person[tag] = value
                offset += length
            persons.append(person)

        self["persons"] = persons


class ATR(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class DIR(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class CardAccess(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"CardAccess: SecurityInfo parse failed ({e})")

    def parse(self):
        from pypassport.doc9303.security_info import SecurityInfoParser
        self["security_infos"] = SecurityInfoParser().parse(self.body)


class CardSecurity(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"CardSecurity: SecurityInfo parse failed ({e})")

    def parse(self):
        from pypassport.doc9303.security_info import SecurityInfoParser
        self["security_infos"] = SecurityInfoParser().parse(self.body)


_CLASS_MAP = {
    "Common": Common,
    "DataGroup1": DataGroup1,
    "DataGroup2": DataGroup2,
    "DataGroup3": DataGroup3,
    "DataGroup4": DataGroup4,
    "DataGroup5": DataGroup5,
    "DataGroup6": DataGroup6,
    "DataGroup7": DataGroup7,
    "DataGroup8": DataGroup8,
    "DataGroup9": DataGroup9,
    "DataGroup10": DataGroup10,
    "DataGroup11": DataGroup11,
    "DataGroup12": DataGroup12,
    "DataGroup13": DataGroup13,
    "DataGroup14": DataGroup14,
    "DataGroup15": DataGroup15,
    "DataGroup16": DataGroup16,
    "SOD": SOD,
    "ATR": ATR,
    "DIR": DIR,
    "CardAccess": CardAccess,
    "CardSecurity": CardSecurity,
}







class DataGroupDump(object):
    """
    Save the passport, a specific dataGroup or some data to the disk.
    """

    def __init__(self, path, ext=""):
        """
        @param path: The path where the dump will be stored.
        @param ext: File extension
        @type path: A string
        @raise Exception: If the specified directory in invalid.
        """
        if os.path.isdir(path):
            self._path = path
            self._path += os.path.sep
            self._ext = ext
        else:
            raise Exception(path + " is not a valid directory")


    def dump(self, ep, format="FID"):
        """
        Save the dataGroup binaries on the HDD.
        The name format is specified by the format parameter.

        @param ep: The EPassport object.
        @type ep: A dictionary
        @param format: Specify the file name format. (FID, TAG, SEF,...)
        @type format: An element out of the converter.types enumeration.
        """
        for tag in ep:
            self.dumpDG(ep[tag], format)


    def dumpDG(self, dg, format="FID"):
        """
        Save the specified dataGroup on the HDD.

        @param dg: A filled dataGroup object
        @type dg: A dataGroup object
        @param format: Specify the file name format. (FID, TAG, SEF,...)
        @type format: An element out of the converter.types enumeration.
        """
        f = open(self._path + converter.to(format, dg.tag) + self._ext, "wb")
        f.write(dg.file)
        f.close()


    def dumpData(self, data, name):
        """
        Save some data on the HDD. The data can be the binary of a picture for example.
        It will be saved under the name passed as parameter.

        @param data: The binary to save on the HDD
        @type data: A binary string
        @param name: The file name
        @type name: A string
        """
        if data is None:
            return
        f = open(self._path + name, "wb")
        f.write(data)
        f.close()



