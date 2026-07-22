from __future__ import annotations

import logging
import json
import string
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, cast

from pypassport.iso7816 import ISO7816Exception
from pypassport.utils import to_hex_string, to_bytes, parse_tlv
from pypassport.asn1 import asn1_length
from pypassport.iso19794 import BIOMETRIC_PARSERS
from pypassport.doc9303 import converter

# Reference: https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf


def _unwrap_security_infos(data: bytes) -> bytes:
    """Return the raw DER SecurityInfos SET from *data*.

    Some chips (and some card-emulation test tools) nest the SecurityInfos
    SET inside an extra Application-class TLV (e.g. tag 0x42) on top of the
    outer LDS wrapper that is already stripped by read_elementary_file.  When
    that happens the first byte of *data* has class bits 0x40 (Application)
    rather than 0x20 (Constructed Universal, i.e. SET = 0x31).  Strip one
    level of Application-class wrapping so the inner SET reaches pyasn1.
    """
    if data and (data[0] & 0xC0) == 0x40:  # Application-class tag
        try:
            _, inner, _ = parse_tlv(data)
            return inner
        except Exception:
            pass
    return data


# DOC9303-2 pg III-38


tagToName = {
    "5C": "Tag list",
    # DataGroup
    "60": "Common data elements",
    "61": "Template for MRZ data group",
    "63": "Template for Finger biometric data group",
    "65": "Template for digitized facial image",
    "66": "Reserved for Future Use",
    "67": "Template for digitized Signature or usual mark",
    "68": "Template for Machine Assisted Security - Encoded Data",
    "69": "Template for Machine Assisted Security - Structure",
    "6A": "Template for Machine Assisted Security - Substance",
    "6B": "Template for Additional Personal Details",
    "6C": "Template for Additional Document Details",
    "6D": "Optional details (Country Specific)",
    "6E": "Reserved for future use",
    "6F": "Active Authentication Public Key Info",
    "70": "Person to Notify",
    "75": "Template for facial biometric data group",
    "76": "Template for Iris (eye) biometric template",
    "77": "Security Object (EF for security data)",
    "5F01": "LDS Version Number",
    "5F08": "Date of birth (truncated)",
    "5F09": "Compressed image (ANSI/NIST-ITL 1-2000)",
    "5F0A": "Security features - Encoded Data",
    "5F0B": "Security features - Structure",
    "5F0C": "Security features",
    "5F0E": "Full name, in national characters",
    "5F0F": "Other names",
    "5F10": "Personal Number",
    "5F11": "Place of birth",
    "5F12": "Telephone",
    "5F13": "Profession",
    "5F14": "Title",
    "5F15": "Personal Summary",
    "5F16": "Proof of citizenship (10918 image)",
    "5F17": "Other valid TD Numbers",
    "5F18": "Custody information",
    "5F19": "Issuing Authority",
    "5F1A": "Other people on document",
    "5F1B": "Endorsement/Observations",
    "5F1C": "Tax/Exit requirements",
    "5F1D": "Image of document front",
    "5F1E": "Image of document rear",
    "5F1F": "MRZ data elements",
    "5F26": "Date of Issue",
    "5F2E": "Biometric data block",
    "5F36": "Unicode Version Level",
    "5F40": "Compressed image template",
    "5F42": "Address",
    "5F43": "Compressed image template",
    "5F50": "Date data recorded",
    "5F51": "Name of person",
    "5F52": "Telephone",
    "5F53": "Address",
    "5F55": "Date and time document personalized",
    "5F56": "Serial number of personalization system",
    "7F2E": "Biometric data block (enciphered)",
    "7F60": "Biometric Information Template",
    "7F61": "Biometric Information Group Template",
    "80": "ICAO header version",
    "81": "Biometric Type",
    "82": "Biometric subtype",
    "83": "Creation date and time",
    "84": "Validity period",  # (revized in nov 2008)
    "85": "Validity period",  # (since 2008)
    "86": "Creator of biometric reference data",
    "87": "Format Owner",
    "88": "Format Type",
    "89": "Context specific tags",
    "8A": "Context specific tags",
    "8B": "Context specific tags",
    "8C": "Context specific tags",
    "8D": "Context specific tags",
    "8E": "Context specific tags",
    "8F": "Context specific tags",
    "90": "Enciphered hash code",
    "A0": "Context specific constructed data objects",
    "A1": "Repeating template, 1 occurrence Biometric header",
    "A2": "Repeating template, 2 occurrence Biometric header",
    "A3": "Repeating template, 3 occurrence Biometric header",
    "A4": "Repeating template, 4 occurrence Biometric header",
    "A5": "Repeating template, 5 occurrence Biometric header",
    "A6": "Repeating template, 6 occurrence Biometric header",
    "A7": "Repeating template, 7 occurrence Biometric header",
    "A8": "Repeating template, 8 occurrence Biometric header",
    "A9": "Repeating template, 9 occurrence Biometric header",
    "AA": "Repeating template, 10 occurrence Biometric header",
    "AB": "Repeating template, 11 occurrence Biometric header",
    "AC": "Repeating template, 12 occurrence Biometric header",
    "AD": "Repeating template, 13 occurrence Biometric header",
    "AE": "Repeating template, 14 occurrence Biometric header",
    "AF": "Repeating template, 15 occurrence Biometric header",
    "B0": "Repeating template, 0 occurrence Biometric header",
    "B1": "Repeating template, 1 occurrence Biometric header",
    "B2": "Repeating template, 2 occurrence Biometric header",
    "B3": "Repeating template, 3 occurrence Biometric header",
    "B4": "Repeating template, 4 occurrence Biometric header",
    "B5": "Repeating template, 5 occurrence Biometric header",
    "B6": "Repeating template, 6 occurrence Biometric header",
    "B7": "Repeating template, 7 occurrence Biometric header",
    "B8": "Repeating template, 8 occurrence Biometric header",
    "B9": "Repeating template, 9 occurrence Biometric header",
    "BA": "Repeating template, 10 occurrence Biometric header",
    "BB": "Repeating template, 11 occurrence Biometric header",
    "BC": "Repeating template, 12 occurrence Biometric header",
    "BD": "Repeating template, 13 occurrence Biometric header",
    "BE": "Repeating template, 14 occurrence Biometric header",
    "BF": "Repeating template, 15 occurrence Biometric header",
    # DOC9303-2 pg III-40
    "53": "Optional Data",
    "59": "Date of Expiry or valid Until Date",
    "02": "Document Number",
    "5F02": "Check digit - Optional data (ID-3 only)",
    "5F03": "Document Type",
    "5F04": "Check digit - Doc Number",
    "5F05": "Check digit - DOB",
    "5F06": "Expiry date",
    "5F07": "Composite",
    "5F20": "Issuing State or Organization",
    "5F2B": "Date of birth",
    "5F2C": "Nationality",
    "5F35": "Sex",
    "5F57": "Date of birth (6 digit)",
    # From DG1 (information tags)
    "5F28": "Issuing State or Organization",
    "5F5B": "Name of Holder",  # version 2006
    "5B": "Name of Holder",  # version 2008
    "5A": "Document Number",
    # DOC9303-2 pg III-40
    "5F44": "Country of entry/exit",
    "5F45": "Date of entry/exit",
    "5F46": "Port of entry/exit",
    "5F47": "Entry/Exit indicator",
    "5F48": "Length of stay",
    "5F49": "Category (classification)",
    "5F4A": "Inspector reference",
    "5F4B": "Entry/Exit indicator",
    "71": "Template for Electronic Visas",
    "72": "Template for Border Crossing Schemes",
    "73": "Template for Travel Record Data Group",
}

_READABLE_DATE_TAGS = {"59", "5F06", "5F08", "5F26", "5F2B", "5F50", "5F55", "5F57"}
_READABLE_NAME_TAGS = {"5B", "5F0E", "5F0F", "5F1A", "5F51", "5F5B"}
_READABLE_LATIN1_TAGS = {
    "53",
    "59",
    "5A",
    "5B",
    "5F01",
    "5F03",
    "5F06",
    "5F08",
    "5F0E",
    "5F0F",
    "5F10",
    "5F11",
    "5F12",
    "5F13",
    "5F14",
    "5F15",
    "5F17",
    "5F19",
    "5F1A",
    "5F1B",
    "5F1C",
    "5F20",
    "5F26",
    "5F28",
    "5F2B",
    "5F2C",
    "5F35",
    "5F36",
    "5F42",
    "5F44",
    "5F45",
    "5F46",
    "5F47",
    "5F48",
    "5F49",
    "5F4A",
    "5F4B",
    "5F50",
    "5F51",
    "5F52",
    "5F53",
    "5F55",
    "5F56",
    "5F57",
    "5F5B",
}
_READABLE_BINARY_KEYS = {
    "5F09",
    "5F16",
    "5F1D",
    "5F1E",
    "5F2E",
    "5F40",
    "5F43",
    "7F2E",
    "ImageData",
    "primary_image",
    "raw",
}
_READABLE_KEY_NAMES = {
    "bdb_magic": "BDB magic",
    "dg_hashes": "Data group hashes",
    "eci_content_type_oid": "Encapsulated content type OID",
    "lds_version": "LDS version",
    "lds_version_info": "LDS version info",
    "mrz": "MRZ",
    "oid": "OID",
    "parse_errors": "Parse errors",
    "raw_hex": "Raw hex",
    "signer_issuer": "Signer issuer",
    "signer_serial": "Signer serial",
}


def read_elementary_file(tag, iso7816, maxSize=0xDF):
    try:
        expected_tag = converter.to_tag(tag)
        fid = converter.to_fid(expected_tag)
        if converter.to_dg(expected_tag) == "CardAccess":
            # EF.CardAccess is a raw SecurityInfos DER object under the MF,
            # not an LDS EF wrapped in application tag 0x42. Read it through
            # the dedicated MF-aware reader and keep its ASN.1 wrapper intact.
            from pypassport.doc9303.card_access import CardAccessReader

            return CardAccess.from_security_infos(CardAccessReader(iso7816).read())
        logging.info(f"Reading {expected_tag} (FID {fid})...")
        offset = 0

        iso7816.select_elementary_file(fid)

        # Read DG header (to know the body size)
        headerRaw = iso7816.read_binary(offset, 4)
        header = ElementaryFileHeader(headerRaw)
        if header.tag != expected_tag:
            logging.warning("EF %s returned unexpected outer tag %s", expected_tag, header.tag)

        # Read the DG body
        offset += header.headerSize
        logging.debug("Read EF body")
        body = b""
        remaining = header.bodySize

        while remaining:
            toRead = min(remaining, maxSize)
            body += iso7816.read_binary(offset, toRead)
            remaining -= toRead
            offset += toRead

        if header.bodySize != len(body):
            raise Exception(
                "The file is not entirely read: expected: " + str(header.bodySize) + " read: " + str(len(body))
            )

        # Creating the DG
        file = header.raw + body
        class_name = converter.to_class(expected_tag)
        if class_name not in _CLASS_MAP:
            raise ElementaryFileException(f"Unknown class for tag {expected_tag}: {class_name}")
        dg = _CLASS_MAP[class_name](file=file)
        if header.tag != expected_tag:
            dg["actual_outer_tag"] = header.tag
            dg["expected_outer_tag"] = expected_tag
            dg._record_parse_error(
                "outer_tag",
                f"expected outer tag {expected_tag}, got {header.tag}",
                raw=body,
            )
            # Keep the logical EF identity stable for caching and rendering,
            # while preserving the wire-level outer tag above.
            dg.tag = expected_tag
        return dg
    except ISO7816Exception as e:
        sw_str = f"SW={e.sw1:02X}{e.sw2:02X}" if e.sw1 is not None else ""
        logging.debug(f"ISO7816 error reading tag {expected_tag} (FID {fid}): {sw_str} — {e.data}")
        raise


class ElementaryFileException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class ElementaryFileHeader:
    def __init__(self, header):
        if isinstance(header, list):
            header = bytes(header)
        if isinstance(header, str):
            header = to_bytes(header)
        if not isinstance(header, bytes):
            raise ElementaryFileException(f"ElementaryFileHeader: expected bytes, got {type(header).__name__}")
        self.tag = to_hex_string(header[0])
        (self.bodySize, lenSize) = asn1_length(header[1:])
        self.headerSize = lenSize + 1
        self.raw = header[: self.headerSize]


class ElementaryFile(dict):
    def __init__(self, tag="", header=None, body=b"", file=b""):
        self.tag = ""
        self._header: ElementaryFileHeader | None = None
        self._body = b""

        if tag:
            self.tag = tag
        if header:
            self.header = header
        if body:
            self.body = body
        if file:
            self.file = file

    def _set_header(self, header):
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

    def _get_header(self):
        return self._header

    def _set_body(self, body):
        if isinstance(body, list):
            body = bytes(body)
        if isinstance(body, str):
            body = to_bytes(body)
        if not isinstance(body, bytes):
            raise ElementaryFileException(f"ElementaryFile body: expected bytes, got {type(body).__name__}")
        self._body = body
        if self.header:
            self.init_parse()

    def _get_body(self):
        return self._body

    def _set_file(self, file):
        if isinstance(file, list):
            file = bytes(file)
        if isinstance(file, str):
            file = to_bytes(file)
        if not isinstance(file, bytes):
            raise ElementaryFileException(f"ElementaryFile file: expected bytes, got {type(file).__name__}")
        self.header = file[:4]
        header = self.header
        if header is None:
            raise ElementaryFileException("ElementaryFile header could not be parsed")
        offset = header.headerSize
        self.body = file[offset:]

    def _get_file(self):
        if self._header is None:
            raise ElementaryFileException("ElementaryFile is not initialized")
        return self._header.raw + self._body

    def _get_len(self):
        return len(self.file)

    def init_parse(self):
        # logging.debug(f"Body: {self.body}")
        if self.tag not in ["65", "67", "6F", "77"]:
            self.update(self.parse_dict(self.body, context="generic_tlv"))
            self.parse_map()
        else:
            self["raw"] = self.body

    def _record_parse_error(self, context: str, error: Exception | str, *, raw: bytes | None = None) -> None:
        message = str(error)
        errors = self.setdefault("parse_errors", [])
        if not isinstance(errors, list):
            errors = []
            self["parse_errors"] = errors
        detail: dict[str, Any] = {"context": context, "message": message}
        if raw is not None and raw != self.body:
            detail["raw_hex"] = raw.hex().upper()
        errors.append(detail)
        self.setdefault("raw", self.body)

    def parse_dict(self, data, *, context: str | None = None):
        output: dict[str, Any] = {}
        offset = 0
        while offset < len(data):
            try:
                tag, value, total_length = parse_tlv(data[offset:])
            except Exception as e:
                logging.error(f"An error took place while parsing the DataFile. Reason: {e} ({type(e)})")
                output["_unparsed_tail"] = data[offset:]
                if context is not None:
                    self._record_parse_error(context, e, raw=data)
                break
            if tag in output:
                duplicates = output.setdefault("_duplicate_tags", {})
                if isinstance(duplicates, dict):
                    previous = duplicates.setdefault(tag, [output[tag]])
                    if isinstance(previous, list):
                        previous.append(value)
                output[tag] = value
            else:
                output[tag] = value
            offset += total_length
        return output

    def parse_array(self, data):
        output: dict[str, Any] = {}

        tag, value, offset = parse_tlv(data)
        if tag != "02":
            raise ElementaryFileException(f"parse_array: expected tag 02, got {tag}")
        count = int.from_bytes(value, "big")
        output["02"] = count

        array: list[bytes] = []
        for _ in range(count):
            tag, value, length = parse_tlv(data[offset:])
            array.append(value)
            offset += length
        output[tag] = array

        return tag, output, offset

    def parse_map(self):
        if "5C" in self:
            map = self["5C"]
            if not isinstance(map, bytes):
                self._record_parse_error("tag_list", f"expected bytes for 5C tag list, got {type(map).__name__}")
                return
            self["5C"] = []
            index = 0
            while index < len(map):
                current = map[index]
                if (current & 0x1F) == 0x1F:  # BER-TLV multi-byte tag indicator
                    if index + 1 >= len(map):
                        self._record_parse_error("tag_list", "truncated multi-byte tag in 5C tag list", raw=map)
                        self["5C"].append(to_hex_string(current))
                        break
                    reference = [current, map[index + 1]]
                    index += 1
                else:
                    reference = [current]
                self["5C"].append(to_hex_string(reference))
                index += 1

    def print_any(self, node, output="", level=0):
        nl = "\n"
        if isinstance(node, dict):
            for key, value in node.items():
                tab = "    " * level
                try:
                    extra = f" ({tagToName[key]})"
                except KeyError:
                    extra = ""
                output += f"{nl if output else ''}{tab}[{key}]{extra}: "
                output = self.print_any(value, output, level + 1)
        if isinstance(node, list):
            index = 0
            for value in node:
                tab = "    " * level
                name_hint = ""
                if isinstance(value, str):
                    try:
                        name_hint = f" ({tagToName[value.upper()]})"
                    except KeyError:
                        pass
                output += f"{nl if output else ''}{tab}[{index}]{name_hint}: "
                output = self.print_any(value, output, level + 1)
                index += 1
        if isinstance(node, int):
            output += to_hex_string(node)
        if isinstance(node, bytes):
            printable = True
            for char in node:
                if chr(char) not in string.printable:
                    printable = False
                    break
            if printable:
                output += node.decode()
            else:
                output += to_hex_string(node)
        if isinstance(node, str):
            output += node
        return output

    @staticmethod
    def _json_value(value: Any) -> Any:
        if isinstance(value, bytes):
            return value.hex().upper()
        if isinstance(value, dict):
            return {str(key): ElementaryFile._json_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [ElementaryFile._json_value(item) for item in value]
        if isinstance(value, set):
            return [ElementaryFile._json_value(item) for item in sorted(value)]
        if is_dataclass(value):
            return ElementaryFile._json_value(asdict(cast(Any, value)))
        return value

    @staticmethod
    def _readable_tag_reference(tag: str) -> str:
        upper = tag.upper()
        label = tagToName.get(upper)
        return f"{label} [{upper}]" if label else upper

    @staticmethod
    def _readable_key(key: Any, value: Any) -> str:
        text = str(key)
        upper = text.upper()
        if upper == "02" and isinstance(value, int):
            return "Count [02]"
        if upper in tagToName:
            return ElementaryFile._readable_tag_reference(upper)
        if text in _READABLE_KEY_NAMES:
            return _READABLE_KEY_NAMES[text]
        if "_" in text:
            text = text.replace("_", " ")
        return text[:1].upper() + text[1:] if text else text

    @staticmethod
    def _readable_text(value: str, key: str | None) -> str:
        tag = key.upper() if key is not None else ""
        if tag in _READABLE_NAME_TAGS:
            parts = value.split("<<", 1)
            primary = " ".join(parts[0].replace("<", " ").split())
            if len(parts) == 1:
                return primary
            secondary = " ".join(parts[1].replace("<", " ").split())
            return f"{primary}, {secondary}" if secondary else primary
        if tag in _READABLE_DATE_TAGS and value.isdigit():
            if len(value) == 8:
                return f"{value[0:4]}-{value[4:6]}-{value[6:8]}"
            if len(value) == 6:
                return f"{value[0:2]}-{value[2:4]}-{value[4:6]}"
        return value

    @staticmethod
    def _readable_binary_summary(value: bytes) -> dict[str, Any]:
        preview = value[:32].hex().upper()
        if len(value) > 32:
            preview += "..."
        return {
            "binary_length_bytes": len(value),
            "hex_preview": preview,
        }

    @staticmethod
    def _looks_binary_key(key: str | None) -> bool:
        if key is None:
            return False
        return (
            key in _READABLE_BINARY_KEYS
            or key.endswith("_raw")
            or key.endswith("_tail")
            or key.endswith("_unparsed")
            or key.endswith("_unparsed_tail")
        )

    @staticmethod
    def _decode_readable_bytes(value: bytes, key: str | None) -> str | None:
        if not value:
            return ""
        if ElementaryFile._looks_binary_key(key):
            return None
        encodings = ["utf-8"]
        if key is not None and key.upper() in _READABLE_LATIN1_TAGS:
            encodings.append("latin-1")
        for encoding in encodings:
            try:
                decoded = value.decode(encoding)
            except UnicodeDecodeError:
                continue
            if all(char.isprintable() or char in "\r\n\t" for char in decoded):
                return ElementaryFile._readable_text(decoded, key)
        return None

    @classmethod
    def _readable_value(cls, value: Any, *, key: str | None = None) -> Any:
        if isinstance(value, bytes):
            decoded = cls._decode_readable_bytes(value, key)
            return decoded if decoded is not None else cls._readable_binary_summary(value)
        if isinstance(value, dict):
            return {
                cls._readable_key(item_key, item): cls._readable_value(item, key=str(item_key))
                for item_key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            if key is not None and key.upper() == "5C":
                return [
                    cls._readable_tag_reference(item) if isinstance(item, str) else cls._readable_value(item)
                    for item in value
                ]
            return [cls._readable_value(item, key=key) for item in value]
        if isinstance(value, set):
            return [cls._readable_value(item, key=key) for item in sorted(value)]
        if is_dataclass(value):
            return cls._readable_value(asdict(cast(Any, value)), key=key)
        if isinstance(value, str):
            if key in {"tag", "template_tag"}:
                return cls._readable_tag_reference(value)
            return cls._readable_text(value, key)
        return value

    def to_json_dict(self) -> dict[str, Any]:
        """Return the parsed EF content in a JSON-serialisable form."""

        try:
            name = converter.to_dg(self.tag)
        except KeyError:
            name = self.tag
        return {
            "name": name,
            "tag": self.tag,
            "length": len(self.file),
            "raw_file_hex": self.file.hex().upper(),
            "raw_body_hex": self.body.hex().upper(),
            "data": self._json_value(dict(self)),
        }

    def to_readable_dict(self) -> dict[str, Any]:
        """Return a labelled, human-oriented view without changing raw parser keys."""

        try:
            name = converter.to_dg(self.tag)
        except KeyError:
            name = self.tag
        return {
            "name": name,
            "outer_tag": self._readable_tag_reference(self.tag),
            "length_bytes": len(self.file),
            "data": self._readable_value(dict(self)),
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Return a stable JSON rendering of this elementary file."""

        return json.dumps(self.to_json_dict(), indent=indent, sort_keys=True)

    def to_readable_json(self, *, indent: int = 2) -> str:
        """Return a stable JSON rendering with tag labels and decoded text values."""

        return json.dumps(self.to_readable_dict(), indent=indent, sort_keys=True)

    def __str__(self):
        return self.print_any(self)

    header = property(_get_header, _set_header)
    body = property(_get_body, _set_body)
    file = property(_get_file, _set_file)
    len = property(_get_len)


class BiometricTemplates(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)

    def parse(self):
        bitgt = self.get("7F61")
        if not isinstance(bitgt, bytes):
            logging.warning("BiometricTemplates: missing 7F61, storing raw body")
            self._record_parse_error("biometric_templates", "missing 7F61 group template")
            return

        self["7F61_raw"] = bitgt
        self["7F61"] = []
        declared_count: int | None = None
        offset = 0
        try:
            tag, value, consumed = parse_tlv(bitgt)
        except Exception as e:
            self._record_parse_error("biometric_templates", f"malformed 7F61 template: {e}", raw=bitgt)
            self["7F61_unparsed"] = bitgt
            return

        if tag == "02":
            declared_count = int.from_bytes(value, "big")
            self["number_of_instances"] = declared_count
            if len(value) != 1:
                self._record_parse_error(
                    "biometric_templates",
                    f"instance count must be one byte, got {len(value)}",
                    raw=bitgt,
                )
            offset = consumed
        else:
            self._record_parse_error("biometric_templates", f"expected leading count tag 02, got {tag}", raw=bitgt)

        while offset < len(bitgt):
            try:
                tag, bit, bit_length = parse_tlv(bitgt[offset:])
            except Exception as e:
                self._record_parse_error(
                    "biometric_templates", f"malformed 7F61 tail at offset {offset}: {e}", raw=bitgt
                )
                self["7F61_unparsed_tail"] = bitgt[offset:]
                break
            if tag != "7F60":
                self._record_parse_error(
                    "biometric_templates",
                    f"expected 7F60 template at offset {offset}, got {tag}",
                    raw=bitgt,
                )
                extras = self.setdefault("7F61_extra_tlvs", [])
                if isinstance(extras, list):
                    extras.append({"tag": tag, "value": bit})
                offset += bit_length
                continue
            template = {"7F60": self._parse_biometric_template(bit, len(self["7F61"]))}
            self["7F61"].append(template)
            offset += bit_length

        if declared_count is not None and declared_count != len(self["7F61"]):
            self._record_parse_error(
                "biometric_templates",
                f"declared {declared_count} 7F60 templates, parsed {len(self['7F61'])}",
                raw=bitgt,
            )

    def _parse_biometric_template(self, bit: bytes, index: int) -> dict[str, Any]:
        template: dict[str, Any] = {"raw": bit}
        offset = 0
        while offset < len(bit):
            try:
                tag, value, consumed = parse_tlv(bit[offset:])
            except Exception as e:
                self._record_parse_error(
                    f"biometric_template[{index}]",
                    f"malformed TLV at offset {offset}: {e}",
                    raw=bit,
                )
                template["unparsed_tail"] = bit[offset:]
                break

            if tag == "A1":
                bht = self.parse_dict(value, context=f"biometric_template[{index}].bht")
                template["A1"] = bht
                if "87" not in bht or "88" not in bht:
                    self._record_parse_error(
                        f"biometric_template[{index}].bht",
                        "BHT should contain format owner (87) and type (88)",
                        raw=value,
                    )
            elif tag in ("5F2E", "7F2E"):
                template[tag] = value
                self._analyse_biometric_data_block(template, value, index)
            else:
                extras = template.setdefault("extra_tlvs", [])
                if isinstance(extras, list):
                    extras.append({"tag": tag, "value": value})
                template.setdefault(tag, value)
                if offset == 0:
                    self._record_parse_error(
                        f"biometric_template[{index}]",
                        f"expected leading A1 BHT, got {tag}",
                        raw=bit,
                    )
            offset += consumed

        if "A1" not in template:
            self._record_parse_error(f"biometric_template[{index}]", "missing A1 BHT", raw=bit)
        if "5F2E" not in template and "7F2E" not in template:
            self._record_parse_error(f"biometric_template[{index}]", "missing biometric data block", raw=bit)
        return template

    def _analyse_biometric_data_block(self, template: dict[str, Any], bdb: bytes, index: int) -> None:
        magic = bdb[:4]
        analyser = BIOMETRIC_PARSERS.get(magic)
        if analyser is None:
            logging.warning(f"BiometricTemplates: unknown biometric magic {magic!r}, storing raw BDB")
            template["bdb_magic"] = magic
            return
        try:
            parsed = analyser(bdb)
        except Exception as e:
            logging.warning(f"BiometricTemplates: CBEFF parse failed: {e}, storing raw BDB")
            self._record_parse_error(f"biometric_template[{index}].bdb", e, raw=bdb)
            return
        template["meta"] = parsed.metadata
        template["primary_image"] = parsed.primary_image

    def get_biometric_data(self) -> list[bytes]:
        """Return decoded biometric image payloads from every BIT."""

        payloads: list[bytes] = []
        templates = self.get("7F61", [])
        if not isinstance(templates, list):
            return payloads
        for template in templates:
            try:
                bit = template["7F60"]
            except (KeyError, TypeError):
                continue
            meta = bit.get("meta")
            if isinstance(meta, dict):
                facial_images = meta.get("FacialImages")
                if isinstance(facial_images, list):
                    for image in facial_images:
                        if isinstance(image, dict) and isinstance(image.get("ImageData"), bytes):
                            payloads.append(image["ImageData"])
                    if facial_images:
                        continue
            primary_image = bit.get("primary_image")
            if isinstance(primary_image, bytes):
                payloads.append(primary_image)
        return payloads


class DisplayedImageTemplates(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)

    def parse(self):
        try:
            tag, value, offset = self.parse_array(self.body)
        except Exception as e:
            self._record_parse_error("displayed_image_templates", e)
            return
        if tag not in ("5F40", "5F43"):
            self._record_parse_error(
                "displayed_image_templates",
                f"expected tag 5F40 or 5F43, got {tag}",
            )
        self.update(value)

        # If extra data
        while offset < len(self.body):
            try:
                tag, extra, extra_length = parse_tlv(self.body[offset:])
            except Exception as e:
                self._record_parse_error("displayed_image_templates", f"malformed tail at offset {offset}: {e}")
                self["unparsed_tail"] = self.body[offset:]
                break
            self[tag] = extra
            offset += extra_length


class Common(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"EF.COM: parse failed ({e})")
            self._record_parse_error("ef_com", e)

    def parse(self):
        # 5F01: LDS Version Number (e.g. b"0107" → "1.7")
        if "5F01" in self:
            raw = self["5F01"]
            if isinstance(raw, bytes) and len(raw) >= 4:
                try:
                    self["lds_version"] = f"{int(raw[0:2])}.{int(raw[2:4])}"
                except (ValueError, TypeError):
                    self["lds_version"] = raw.decode("ascii", errors="replace")
        # 5F36: Unicode Version Level (e.g. b"040000" → "4.0.0")
        if "5F36" in self:
            raw = self["5F36"]
            if isinstance(raw, bytes) and len(raw) >= 6:
                try:
                    self["unicode_version"] = f"{int(raw[0:2])}.{int(raw[2:4])}.{int(raw[4:6])}"
                except (ValueError, TypeError):
                    self["unicode_version"] = raw.decode("ascii", errors="replace")


def _sod_decode_oid(value_bytes):
    """Decode raw OID value bytes (no tag/length) to a dotted-string."""
    if not value_bytes:
        return ""
    result = []
    first = value_bytes[0]
    result.append(str(first // 40))
    result.append(str(first % 40))
    idx = 1
    acc = 0
    while idx < len(value_bytes):
        b = value_bytes[idx]
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            result.append(str(acc))
            acc = 0
        idx += 1
    return ".".join(result)


_DN_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}


def _sod_parse_name(name_val):
    """Parse raw X.509 Name value bytes → dict of short-name → value."""
    attrs = {}
    pos = 0
    while pos < len(name_val):
        tag, rdn_val, consumed = parse_tlv(name_val[pos:])
        pos += consumed
        rdn_pos = 0
        while rdn_pos < len(rdn_val):
            tag2, atv_val, atv_consumed = parse_tlv(rdn_val[rdn_pos:])
            rdn_pos += atv_consumed
            tag3, oid_val, oid_consumed = parse_tlv(atv_val)
            oid_str = _sod_decode_oid(oid_val)
            _, str_val, _ = parse_tlv(atv_val[oid_consumed:])
            try:
                decoded = str_val.decode("utf-8")
            except Exception:
                decoded = str_val.decode("latin-1", errors="replace")
            short = _DN_OID_NAMES.get(oid_str, oid_str)
            attrs[short] = decoded
    return attrs


def _sod_parse_signer_infos(si_set_val):
    """Parse SET OF SignerInfo value bytes → list of dicts."""
    from pypassport.der_object_identifier import OID

    infos = []
    pos = 0
    while pos < len(si_set_val):
        tag, si_val, consumed = parse_tlv(si_set_val[pos:])
        pos += consumed
        try:
            si_info = _sod_parse_one_signer_info(si_val, OID)
        except Exception as e:
            logging.warning(f"SOD: SignerInfo parse failed: {e}")
            si_info = {}
        infos.append(si_info)
    return infos


def _sod_parse_one_signer_info(si_val, OID):
    si_info: dict[str, Any] = {}
    si_pos = 0

    # version INTEGER
    tag2, v_val, v_consumed = parse_tlv(si_val[si_pos:])
    si_pos += v_consumed
    si_info["version"] = int.from_bytes(v_val, "big")

    # sid: IssuerAndSerialNumber (30) or SubjectKeyIdentifier [0] (80)
    tag2, sid_val, sid_consumed = parse_tlv(si_val[si_pos:])
    si_pos += sid_consumed
    if tag2 == "30":
        sid_pos = 0
        tag3, issuer_val, issuer_consumed = parse_tlv(sid_val[sid_pos:])
        sid_pos += issuer_consumed
        si_info["signer_issuer"] = _sod_parse_name(issuer_val)
        tag3, serial_val, _ = parse_tlv(sid_val[sid_pos:])
        si_info["signer_serial"] = serial_val.hex()

    # digestAlgorithm AlgorithmIdentifier
    tag2, da_val, da_consumed = parse_tlv(si_val[si_pos:])
    si_pos += da_consumed
    tag3, da_oid_val, _ = parse_tlv(da_val)
    da_oid = _sod_decode_oid(da_oid_val)
    si_info["digest_algorithm"] = OID.get(da_oid, da_oid)

    # skip optional signedAttrs [0]
    tag2, next_val, next_consumed = parse_tlv(si_val[si_pos:])
    if tag2 == "A0":
        si_pos += next_consumed
        tag2, next_val, next_consumed = parse_tlv(si_val[si_pos:])

    # signatureAlgorithm AlgorithmIdentifier
    if tag2 == "30":
        tag3, sa_oid_val, _ = parse_tlv(next_val)
        sa_oid = _sod_decode_oid(sa_oid_val)
        si_info["signature_algorithm"] = OID.get(sa_oid, sa_oid)

    return si_info


class SOD(ElementaryFile):
    def init_parse(self):
        # Defer all parsing to parse(); do not pre-populate "raw"
        pass

    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"SOD: parse failed ({e}), keeping raw body")
            self._record_parse_error("sod", e)

    def parse(self):
        from pypassport.asn1 import LDSSecurityObject
        from pypassport.der_object_identifier import OID
        from pypassport.doc9303 import cms
        from pyasn1.codec.der import decoder as der_dec

        _partial = False
        body = self.body

        # ContentInfo: SEQUENCE { OID, [0] EXPLICIT SignedData }
        _, ci_val, _ = parse_tlv(body)

        # contentType OID
        _, oid_val, offset = parse_tlv(ci_val)
        self["content_type_oid"] = _sod_decode_oid(oid_val)

        # [0] EXPLICIT wrapper → SignedData SEQUENCE
        _, a0_inner, _ = parse_tlv(ci_val[offset:])
        _, sd_body, _ = parse_tlv(a0_inner)

        pos = 0

        # version INTEGER
        _, v_val, consumed = parse_tlv(sd_body[pos:])
        pos += consumed
        self["version"] = int.from_bytes(v_val, "big")

        # digestAlgorithms SET OF AlgorithmIdentifier
        _, da_val, consumed = parse_tlv(sd_body[pos:])
        pos += consumed
        algs = []
        da_pos = 0
        while da_pos < len(da_val):
            _, alg_seq_val, alg_consumed = parse_tlv(da_val[da_pos:])
            da_pos += alg_consumed
            _, alg_oid_val, _ = parse_tlv(alg_seq_val)
            oid_str = _sod_decode_oid(alg_oid_val)
            algs.append(OID.get(oid_str, oid_str))
        self["digest_algorithms"] = algs

        # encapContentInfo SEQUENCE
        _, eci_val, consumed = parse_tlv(sd_body[pos:])
        pos += consumed
        _, eci_oid_val, eci_offset = parse_tlv(eci_val)
        self["eci_content_type_oid"] = _sod_decode_oid(eci_oid_val)

        # eContent [0] EXPLICIT OCTET STRING → DER-encoded LDSSecurityObject
        if eci_offset < len(eci_val):
            _, a0_eci, _ = parse_tlv(eci_val[eci_offset:])
            _, lds_der, _ = parse_tlv(a0_eci)
            try:
                lds_obj, _ = der_dec.decode(lds_der, asn1Spec=LDSSecurityObject())
                hash_alg_oid = str(lds_obj["hashAlgorithm"]["algorithm"])
                self["hash_algorithm_oid"] = hash_alg_oid
                self["hash_algorithm"] = OID.get(hash_alg_oid, hash_alg_oid)
                self["lds_version"] = int(lds_obj["version"])
                dg_hashes = {}
                for h in lds_obj["dataGroupHashValues"]:
                    dg_num = int(h["dataGroupNumber"])
                    dg_hashes[dg_num] = bytes(h["dataGroupHashValue"]).hex()
                self["dg_hashes"] = dg_hashes
                lds_vi = lds_obj.getComponentByName("ldsVersionInfo")
                if lds_vi is not None and lds_vi.hasValue():

                    def _any_to_str(any_val):
                        raw = bytes(any_val)
                        _, val, _ = parse_tlv(raw)
                        return val.decode("ascii", errors="replace")

                    self["lds_version_info"] = {
                        "lds_version": _any_to_str(lds_vi["ldsVersion"]),
                        "unicode_version": _any_to_str(lds_vi["unicodeVersion"]),
                    }
            except Exception as e:
                logging.warning(f"SOD: LDSSecurityObject decode failed: {e}")
                self._record_parse_error("sod.lds_security_object", e)
                _partial = True

        # certificates [0] IMPLICIT, crls [1] IMPLICIT, signerInfos SET (31)
        while pos < len(sd_body):
            tag, val, consumed = parse_tlv(sd_body[pos:])
            pos += consumed
            if tag == "A0":
                certs = []
                c_pos = 0
                while c_pos < len(val):
                    _, cert_val, cert_consumed = parse_tlv(val[c_pos:])
                    cert_der = val[c_pos : c_pos + cert_consumed]
                    c_pos += cert_consumed
                    try:
                        certs.append(cms.certificate_summary(cert_der))
                    except Exception as e:
                        logging.warning(f"SOD: certificate parse failed: {e}")
                        certs.append({"raw": cert_val.hex()})
                        self._record_parse_error("sod.certificate", e, raw=cert_der)
                        _partial = True
                self["certificates"] = certs
            elif tag == "31":
                try:
                    self["signer_infos"] = _sod_parse_signer_infos(val)
                except Exception as e:
                    logging.warning(f"SOD: signer_infos parse failed: {e}")
                    self._record_parse_error("sod.signer_infos", e, raw=val)
                    _partial = True

        if _partial:
            self.setdefault("raw", body)


class DataGroup1(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG1: parse failed ({e}), keeping raw MRZ bytes")
            self._record_parse_error("dg1", e)

    def parse(self):
        if "5F1F" not in self:
            raise ElementaryFileException("DG1: missing MRZ tag 5F1F")
        raw = self["5F1F"]
        length = len(raw)
        try:
            data = raw.decode("ascii")
        except (UnicodeDecodeError, AttributeError):
            data = raw.decode("latin-1")

        # Always preserve the raw MRZ string as a fallback
        self["5F1F"] = {"mrz": data}

        if length == 90:  # TD1: 3 lines × 30 chars
            self._parse_td1(data)
        elif length == 72:  # TD2: 2 lines × 36 chars
            self._parse_td2(data)
        elif length == 88:  # TD3 (passport): 2 lines × 44 chars
            self._parse_td3(data)
        else:
            logging.warning(f"DG1: unknown MRZ length {length}, raw MRZ stored under 'mrz'")

    def _parse_td1(self, data):
        # ICAO 9303 Part 3 — TD1 (90 chars, 3 lines of 30)
        # Line 1
        self["5F1F"]["5F03"] = data[0:2]  # Document type
        self["5F1F"]["5F28"] = data[2:5]  # Issuing state
        self["5F1F"]["5A"] = data[5:14]  # Document number
        self["5F1F"]["5F04"] = data[14:15]  # Check digit — doc number
        self["5F1F"]["53_L1"] = data[15:30]  # Optional data (line 1)
        # Line 2
        self["5F1F"]["5F57"] = data[30:36]  # Date of birth
        self["5F1F"]["5F05"] = data[36:37]  # Check digit — DOB
        self["5F1F"]["5F35"] = data[37:38]  # Sex
        self["5F1F"]["59"] = data[38:44]  # Date of expiry
        self["5F1F"]["5F06"] = data[44:45]  # Check digit — expiry
        self["5F1F"]["5F2C"] = data[45:48]  # Nationality
        self["5F1F"]["53"] = data[48:59]  # Optional data (line 2)
        self["5F1F"]["5F07"] = data[59:60]  # Composite check digit
        # Line 3
        self["5F1F"]["5B"] = data[60:90]  # Holder name (primary<<secondary)
        self["5F1F"]["5F5B"] = data[60:90]  # Alias for cross-TD compat

    def _parse_td2(self, data):
        # ICAO 9303 Part 3 — TD2 (72 chars, 2 lines of 36)
        # Line 1
        self["5F1F"]["5F03"] = data[0:2]  # Document type
        self["5F1F"]["5F28"] = data[2:5]  # Issuing state
        self["5F1F"]["5B"] = data[5:36]  # Holder name
        self["5F1F"]["5F5B"] = data[5:36]  # Alias for cross-TD compat
        # Line 2
        self["5F1F"]["5A"] = data[36:45]  # Document number
        self["5F1F"]["5F04"] = data[45:46]  # Check digit — doc number
        self["5F1F"]["5F2C"] = data[46:49]  # Nationality
        self["5F1F"]["5F57"] = data[49:55]  # Date of birth
        self["5F1F"]["5F05"] = data[55:56]  # Check digit — DOB
        self["5F1F"]["5F35"] = data[56:57]  # Sex
        self["5F1F"]["59"] = data[57:63]  # Date of expiry
        self["5F1F"]["5F06"] = data[63:64]  # Check digit — expiry
        self["5F1F"]["53"] = data[64:71]  # Optional data
        self["5F1F"]["5F07"] = data[71:72]  # Composite check digit

    def _parse_td3(self, data):
        # ICAO 9303 Part 3 — TD3 / passport (88 chars, 2 lines of 44)
        # Line 1
        self["5F1F"]["5F03"] = data[0:2]  # Document type
        self["5F1F"]["5F28"] = data[2:5]  # Issuing state
        self["5F1F"]["5F5B"] = data[5:44]  # Holder name (primary<<secondary)
        self["5F1F"]["5B"] = data[5:44]  # Alias for cross-TD compat
        # Line 2
        self["5F1F"]["5A"] = data[44:53]  # Document number
        self["5F1F"]["5F04"] = data[53:54]  # Check digit — doc number
        self["5F1F"]["5F2C"] = data[54:57]  # Nationality
        self["5F1F"]["5F57"] = data[57:63]  # Date of birth
        self["5F1F"]["5F05"] = data[63:64]  # Check digit — DOB
        self["5F1F"]["5F35"] = data[64:65]  # Sex
        self["5F1F"]["59"] = data[65:71]  # Date of expiry
        self["5F1F"]["5F06"] = data[71:72]  # Check digit — expiry
        self["5F1F"]["53"] = data[72:86]  # Personal number / optional data
        self["5F1F"]["5F02"] = data[86:87]  # Check digit — personal number
        self["5F1F"]["5F07"] = data[87:88]  # Composite check digit


class DataGroup2(BiometricTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG2: parse failed ({e}), keeping raw body")
            self._record_parse_error("dg2", e)


class DataGroup3(BiometricTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG3: parse failed ({e}), keeping raw body")
            self._record_parse_error("dg3", e)


class DataGroup4(BiometricTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG4: parse failed ({e}), keeping raw body")
            self._record_parse_error("dg4", e)


class DataGroup5(DisplayedImageTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG5: parse failed ({e}), keeping raw body")
            self._record_parse_error("dg5", e)


class DataGroup6(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Reserved for futur use


class DataGroup7(DisplayedImageTemplates):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG7: parse failed ({e}), keeping raw body")
            self._record_parse_error("dg7", e)


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
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG11: parse failed ({e}), keeping raw TLV data")
            self._record_parse_error("dg11", e)

    def parse(self):
        if "5C" not in self:
            return
        # ICAO 9303 Part 10 §4.7.11: A0 wraps a counted list of 5F0F
        # "other name" values. 5F17 is plain text separated by '<', not a
        # counted array.
        if "A0" in self["5C"] and "A0" in self:
            try:
                _, parsed, _ = self.parse_array(self["A0"])
                self["A0"] = parsed
            except Exception as e:
                logging.warning(f"DG11: A0 array parse failed: {e}")
                self._record_parse_error("dg11.a0", e, raw=self["A0"])


class DataGroup12(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG12: parse failed ({e}), keeping raw TLV data")
            self._record_parse_error("dg12", e)

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
                self._record_parse_error("dg12.a0", e, raw=self["A0"])


class DataGroup13(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Proprietary usage


class DataGroup14(ElementaryFile):
    def init_parse(self):
        # The body is a SecurityInfos SET; decode it in parse() rather than
        # walking it as a generic TLV dict.
        pass

    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG14: SecurityInfo parse failed ({e}), keeping raw body")
            self._record_parse_error("dg14", e)

    def parse(self):
        from pypassport.doc9303.security_info import parse_security_infos

        self["security_infos"] = parse_security_infos(_unwrap_security_infos(self.body))


class DataGroup15(ElementaryFile):
    def init_parse(self):
        # The body is raw DER SubjectPublicKeyInfo consumed directly by
        # active_authentication.py via .body; the structured view is built
        # in parse() instead of the generic TLV walk.
        pass

    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG15: SubjectPublicKeyInfo parse failed ({e}), keeping raw body")
            self._record_parse_error("dg15", e)

    def parse(self):
        # Body is raw DER SubjectPublicKeyInfo; decode it into algorithm and
        # key details without disturbing the raw body.
        from pypassport.doc9303.security_info import describe_spki_from_der

        self.update(describe_spki_from_der(self.body))


class DataGroup16(ElementaryFile):
    def init_parse(self):
        # DG16 is a counted sequence of Ax templates, not a flat TLV map.
        pass

    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"DG16: parse failed ({e})")
            self._record_parse_error("dg16", e)

    def parse(self):
        # ICAO 9303 Part 10 §4.7.16: DG16 is encoded as one leading count
        # (tag 02) followed by Ax templates, one template per person.
        if not self.body:
            return

        data = self.body
        count: int | None = None
        offset = 0
        try:
            tag, value, consumed = parse_tlv(data)
        except Exception as e:
            self._record_parse_error("dg16", f"malformed leading TLV: {e}")
            self["unparsed_tail"] = data
            return
        if tag == "02":
            count = int.from_bytes(value, "big")
            self["number_of_templates"] = count
            if len(value) != 1:
                self._record_parse_error("dg16", f"template count must be one byte, got {len(value)}")
            offset = consumed
        else:
            self._record_parse_error("dg16", f"expected leading count tag 02, got {tag}")

        persons: list[dict[str, Any]] = []
        self["persons"] = persons
        while offset < len(data):
            try:
                template_tag, template_value, length = parse_tlv(data[offset:])
            except Exception as e:
                self._record_parse_error("dg16", f"malformed template at offset {offset}: {e}")
                self["unparsed_tail"] = data[offset:]
                break
            if not template_tag.startswith("A"):
                self._record_parse_error("dg16", f"expected Ax person template, got {template_tag}", raw=template_value)
                extras = self.setdefault("extra_tlvs", [])
                if isinstance(extras, list):
                    extras.append({"tag": template_tag, "value": template_value})
            else:
                person = self.parse_dict(template_value, context=f"dg16.{template_tag}")
                person["template_tag"] = template_tag
                persons.append(person)
            offset += length

        if count is not None and len(persons) != count:
            self._record_parse_error("dg16", f"declared {count} person templates, parsed {len(persons)}")


class ATR(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class DIR(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class CardAccess(ElementaryFile):
    def init_parse(self):
        # EF.CardAccess is parsed from the complete raw SecurityInfos object in
        # parse(); do not generic-TLV parse only the body after its SET header.
        pass

    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"CardAccess: SecurityInfo parse failed ({e})")
            self._record_parse_error("card_access", e)

    @classmethod
    def from_security_infos(cls, raw: bytes) -> "CardAccess":
        obj = cls(file=raw)
        # Keep the logical EF identity stable even though the raw ASN.1 object
        # starts with SET/SEQUENCE (31/30), not the legacy display tag 42.
        obj["encoding_tag"] = obj.tag
        obj.tag = converter.to_tag("CardAccess")
        return obj

    def parse(self):
        from pypassport.doc9303.security_info import SecurityInfoParser

        raw = self.file
        self["security_infos"] = SecurityInfoParser().parse(_unwrap_security_infos(raw))
        self["raw"] = raw


class CardSecurity(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        try:
            self.parse()
        except Exception as e:
            logging.warning(f"CardSecurity: SecurityInfo parse failed ({e})")
            self._record_parse_error("card_security", e)

    def parse(self):
        from pypassport.doc9303.security_info import SecurityInfoParser

        self["security_infos"] = SecurityInfoParser().parse(_unwrap_security_infos(self.body))


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


class DataGroupDump:
    """Save passport data groups and extracted files to one directory."""

    def __init__(self, path, ext=""):
        self._path = Path(path).expanduser()
        if not self._path.is_dir():
            raise ValueError(f"{self._path} is not a valid directory")
        self._ext = ext

    def dump(self, ep):
        """Save every loaded data group using canonical logical names."""

        for tag in ep:
            self.dump_dg(ep[tag])

    def dump_dg(self, dg):
        """Save one data group using its canonical logical name."""

        name = converter.to_dg(dg.tag).replace("/", "_")
        (self._path / f"{name}{self._ext}").write_bytes(dg.file)

    def dump_data(self, data, name):
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
        (self._path / name).write_bytes(data)
