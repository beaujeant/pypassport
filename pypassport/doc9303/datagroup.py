import os
import logging
import string

from pypassport.iso7816 import ISO7816Exception
from pypassport.tlvparser import TLVParser, TLVParserException
from pypassport import hexfunctions
from pypassport.utils import toHexString, toBytes, parseTLV
from pypassport.asn1 import asn1Length
from pypassport.iso19794 import ISO19794_5
from pypassport.doc9303 import converter
from pypassport.singleton import Singleton

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

        """
        ##############
        # First option

        # Read DG header (to know the body size)
        headerRaw = iso7816.readBinarySF(converter.toSFID(tag), offset, 4)
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
            body += iso7816.readBinarySF(converter.toSFID(tag), offset, toRead)
            remaining -= toRead
            offset += toRead
        """

        ###############
        # Second option

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
        return eval(converter.toClass(tag))(file=file)
    except ISO7816Exception as e:
        raise e
    #except Exception as e:
    #    logging.error(f"Could not create the elementary file {tag}. Reason: {e}")
    #    return None


class ElementaryFileException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class ElementaryFileHeader():
    def __init__(self, header):
        if isinstance(header, list):
            header = bytes(header)
        if isinstance(header, str):
            header = toBytes(header)
        assert isinstance(header, bytes)
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
        assert isinstance(body, bytes)
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
        assert isinstance(file, bytes)
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
        assert tag == "02"
        output["02"] = int.from_bytes(value)

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
                if (current & 0x5F) == 0x5F:
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
        assert "7F61" in self
        # Biometric Information Template Group Template
        bitgt = self["7F61"]
        self["7F61"] = []

        tag, value, offset = parseTLV(bitgt)
        assert tag == "02"
        for i in range(int.from_bytes(value)):
            # Biometric Group Template
            tag, bit, bit_length = parseTLV(bitgt[offset:])
            assert tag == "7F60"
            self["7F61"].append({"7F60": {}})

            # Biometric Header Template
            tag, bht, bht_length = parseTLV(bit)
            assert tag == "A1"
            self["7F61"][i]["7F60"]["A1"] = self.parse_dict(bht)

            # Biometric Data Block
            tag, bdb, _ = parseTLV(bit[bht_length:])
            assert tag == "5F2E" or tag == "7F2E"
            self["7F61"][i]["7F60"]["meta"], meta_len = ISO19794_5.analyse(bdb)
            self["7F61"][i]["7F60"][tag] = bdb[meta_len:]

            offset += bit_length
        # If extra data
        while offset < len(bitgt):
            tag, extra, extra_length = parseTLV(bitgt[offset:])
            self["7F61"][tag] = extra
            offset += extra_length


class DisplayedImageTemplates(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
    
    def parse(self):
        tag, value, offset = self.parse_array(self.body)
        assert tag in ["5F40", "5F43"]
        self.update(value)

        # If extra data
        while offset < len(self.body):
            tag, extra, extra_length = parseTLV(self.body[offset:])
            self[tag] = extra
            offset += extra_length


class Common(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class SOD(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class DataGroup1(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()

    def parse(self):
        assert "5F1F" in self
        length = len(self["5F1F"])
        data = self["5F1F"].decode()
        self["5F1F"] = {}
        if length == 0x5A:
            self._parseTD1(data)
        elif length == 0x48:
            self._parseTD2(data)
        elif length == 0x58:
            self._parseTD3(data)
        else:
            logging.error("Unknown DG1 size")

    def _parseTD1(self, data):
        self["5F1F"]["5F03"] = data[0:2]
        self["5F1F"]["5F28"] = data[2:5]
        self["5F1F"]["5A"]   = data[5:14]
        self["5F1F"]["5F04"] = data[14:15]
        self["5F1F"]["53"]   = data[15:30]
        self["5F1F"]["5F57"] = data[30:36]
        self["5F1F"]["5F05"] = data[36:37]
        self["5F1F"]["5F35"] = data[37:38]
        self["5F1F"]["59"]   = data[38:44]
        self["5F1F"]["5F06"] = data[44:45]
        self["5F1F"]["5F2C"] = data[45:48]
        self["5F1F"]["53"]  += data[48:59]
        self["5F1F"]["5F07"] = data[59:60]
        self["5F1F"]["5B"]   = data[60:]

    def _parseTD2(self, data):
        self["5F1F"]["5F03"] = data[0:2]
        self["5F1F"]["5F28"] = data[2:5]
        self["5F1F"]["5B"]   = data[5:36]
        self["5F1F"]["5A"]   = data[36:45]
        self["5F1F"]["5F04"] = data[45]
        self["5F1F"]["5F2C"] = data[46:49]
        self["5F1F"]["5F57"] = data[49:55]
        self["5F1F"]["5F05"] = data[55]
        self["5F1F"]["5F35"] = data[56]
        self["5F1F"]["59"]   = data[57:63]
        self["5F1F"]["5F06"] = data[63]
        self["5F1F"]["53"]   = data[64:71]
        self["5F1F"]["5F07"] = data[71]

    def _parseTD3(self, data):
        self["5F1F"]["5F03"] = data[0:2]
        self["5F1F"]["5F28"] = data[2:5]
        self["5F1F"]["5F5B"] = data[5:44]
        self["5F1F"]["5A"]   = data[44:53]
        self["5F1F"]["5F04"] = data[53]
        self["5F1F"]["5F2C"] = data[54:57]
        self["5F1F"]["5F57"] = data[57:63]
        self["5F1F"]["5F05"] = data[63]
        self["5F1F"]["5F35"] = data[64]
        self["5F1F"]["59"]   = data[65:71]
        self["5F1F"]["5F06"] = data[71]
        self["5F1F"]["53"]   = data[72:86]
        self["5F1F"]["5F02"] = data[86]
        self["5F1F"]["5F07"] = data[87]


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
    def __init__(self, file=None):
        super().__init__(file=file)
        #self.parse()

    def parse(self):
        assert "A0" in self
        tag, value, offset = self.parse_array(self["A0"])
        assert tag == "5F0F"
        self["A0"].update(value)


class DataGroup12(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        self.parse()

    def parse(self):
        if "A0" in self["5C"]:
            tag, value, offset = self.parse_array(self["A0"])
            assert tag == "5F0F"
            self["A0"].update(value)


class DataGroup13(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # Proprietary usage


class DataGroup14(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)
        # To be implemtend


class DataGroup15(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class DataGroup16(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class ATR(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class DIR(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class CardAccess(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)


class CardSecurity(ElementaryFile):
    def __init__(self, file=None):
        super().__init__(file=file)











class DataGroup2Old(ElementaryFile):

    def parse(self):
        self._byteNb = 0

        # 7F61 (Biometric Information Group Template)
        assert self._getTag() == "7F61", "Reading GD2: Expecting a Biometric Information Group Template (7F61)."
        length = self._getLength()

        tag = self._getTag()
        self[tag] = self._getValue()
        nbInstance = hexfunctions.binToHex(self[tag])

        for x in range(nbInstance):
            # 7F60
            tag = self._getTag()
            self._getLength()
            # A1
            templateID = self._getTag()
            # Read A
            v = self._getValue()
            dgf = DataGroupFile()
            dgf.body = v
            dg = DataGroup(dgf)
            dg.parse()
            data = dg
            # Transform the binary data into usable data
            for x in data:
                data[x] = hexfunctions.binToHexRep(data[x])
            # 5F2E or 7F2E
            tag = self._getTag()
            value = self._getValue()
            headerSize, data['meta'] = ISO19794_5.analyse(hexfunctions.binToHexRep(value))

            data[tag] = value[headerSize:]
            self[templateID] = {}
            self[templateID] = data

        return self


class DataGroup3Old(DataGroup2):
    def __init__(self, dgFile):
        DataGroup2.__init__(self, dgFile)


class DataGroup4Old(DataGroup2):
    def __init__(self, dgFile):
        DataGroup2.__init__(self, dgFile)


class DataGroup5Old(ElementaryFile):
    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)


    def parse(self):
        """
        The returned value is a dictionary with two keys:
            1. '02': The number of instances
            2. '5F40' or '5F43' : A list of displayed portrait or A list of displayed signature"
                The value is a list of list
        ex:
            - {'02': [2], '5F40' : [[0x..,0x..,0x..], [0x..,0x..,0x..]]}
            - {'02': [1], '5F43' : [[0x..,0x..,0x..]]}

        Each values of the dictionary are in a list of hexadecimal/decimal values.
        """

        self._byteNb = 0
        tag = self._getTag()
        self[tag] = self._getValue()
        nbInstance = hexfunctions.binToHex(self[tag])


        data = []

        for x in range(nbInstance):
            tag = self._getTag()
            data.append(self._getValue())

        self[tag] = data

        return self


class DataGroup6Old(DataGroup5):
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)


class DataGroup7Old(DataGroup5):
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)


class DataGroup8Old(DataGroup5):
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)


class DataGroup9Old(DataGroup5):
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)


class DataGroup10Old(DataGroup5):
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)


class DataGroup11Old(ElementaryFile):
    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)

    def parse(self):
        super(DataGroup11, self).parse()

        if "5F2B" in self:
            if len(hexfunctions.binToHexRep(self["5F2B"])) == 8:
                self["5F2B"] = hexfunctions.binToHexRep(self["5F2B"])

        return self


class DataGroup12Old(ElementaryFile):
    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)


    def parse(self):
        super(DataGroup12, self).parse()

        if "5F26" in self:
            if len(hexfunctions.binToHexRep(self["5F26"])) == 8:
                self["5F26"] = hexfunctions.binToHexRep(self["5F26"])

        if "5F55" in self:
            if len(hexfunctions.binToHexRep(self["5F55"])) == 14:
                self["5F26"] = hexfunctions.binToHexRep(self["5F55"])

        return self


class DataGroup13Old(ElementaryFile):
    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)


class DataGroup14Old(ElementaryFile):

    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)#Reserved for future use (RFU)


    def parse(self):
        return self


class DataGroup15Old(ElementaryFile):
    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)


    def parse(self):
        return self


class DataGroup16Old(ElementaryFile):
    def __init__(self, dgFile):
        ElementaryFile.__init__(self, dgFile)


    def parse(self):
        #Read the number of templates
        self._tagOffset = 0
        nbInstance = hexfunctions.binToHex(self._getValue())

        for i in range(nbInstance):
            #Read each Template Element
            self[i] = self._parseTemplate(self._getValue())

        return self


#####
# NEED MORE DEBUG BUT SHOULD BE DELETED
# MOVE THE FUNCTION AS STATIC TO DataGroupReader CLASS
####


class DataGroupFactory(Singleton):
    def create(self, dgFile):
        dg = eval(converter.toClass(dgFile.tag))(dgFile)
        try:
            dg.parse()
        except Exception as msg:
            self.log("Parsing failed: " + str(msg), converter.toDG(dg.tag))
        return dg


class DataGroupReader():
    """
    Read a specific dataGroup from the passport.
    This is the superclass defining the interface for the classes implementing the reading.
    """

    def __init__(self, iso7816, maxSize = 0xDF):
        """
        @param iso7816: The layer sending iso7816 apdu to the reader.
        @type iso7816: A iso7816 object
        @param maxSize: The maximum buffer size accepted by the reader.
        @type maxSize: An integer (hexa)
        """
        self._iso7816 = iso7816
        self._file = ElementaryFile()
        self._bodySize = 0
        self._offset = 0
        self._maxSize = maxSize


    def readDG(self, dg):
        """
        Read the specified dataGroup and return the file in two parts:

        A dataGroup::
            6C 40
                5C   06     5F195F265F1A
                5F19 18     UNITED STATES OF AMERICA
                5F26 08     20020531
                5F1A 0F     SMITH<<BRENDA<P

            1. The header::
                6C 40
            2. The body ::
                5C   06     5F195F265F1A
                5F19 18     UNITED STATES OF AMERICA
                5F26 08     20020531
                5F1A 0F     SMITH<<BRENDA<P

        """
        logging.info(f"Reading {dg}...")
        self.offset = 0
        self._iso7816.selectElementaryFile(converter.toFID(dg))
        self.file = DataGroupFile()

        headerRaw = self._iso7816.readBinary(self.offset, 4)
        self.file.header = DataGroupHeader(headerRaw)
        if(int(converter.toTAG(dg), 16) != self.file.header.tag):
            raise DataGroupException(f"Wrong AID: {hex(self.file.header.tag)} instead of " + str(self.file.tag))

        self.file.body = self._readBody()

        return self._file


    @staticmethod
    def parse(dgFile):
        dg = eval(converter.toClass(dgFile.tag))(dgFile)
        try:
            dg.parse()
        except Exception as msg:
            logging.info("Parsing failed ({}): {}".format(converter.toDG(dg.tag), msg))
        return dg


    def _readHeader(self, dg):
        logging.debug(f"Read EF header")
        header = self._iso7816.readBinary(self.offset, 4)
        (self._bodySize, self.offset) = asn1Length(header[1:])
        logging.debug(f"Body size: {self._bodySize} - Offset: {self.offset}")

        self.offset += 1

        if(int(converter.toTAG(dg), 16) != header[0]):
            raise DataGroupException("Wrong AID: " + hexfunctions.binToHexRep(header[0]) + " instead of " + str(self.file.tag))

        return header[:self.offset]


    def _readBody(self):
        logging.debug(f"Read EF body")
        body = b""
        remaining = self._bodySize

        while remaining:
            toRead = min(remaining, self._maxSize)
            body += self._iso7816.readBinary(self.offset, toRead)
            remaining -= toRead
            self.offset += toRead

        if self._bodySize != len(body):
            raise Exception("The file is not entirely read: expected: " + str(self._bodySize) + " read: " + str(len(body)))

        return body


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



class DataGroupOld(ElementaryFile):
    def __init__(self, tag="", header=None, body=b"", file=b""):
        super().__init__(tag, header, body, file) 
        self.data = {}

    def parse(self):
        try:
            while self.offset < self.len:
                tag, value, total_length = parseTLV()
                self.data[tag] = value
                self.offset += total_length
        except Exception as e:
            logging.error(f"An error took place while parsing the DataFile. Reason: {e}")

        # Parse the presence amp
        try:
            if "5C" in self.data:
                self.data["5C"] = self._parseDataElementPresenceMap(self["5C"])
        except TLVParserException as msg:
            raise ElementaryFileException(msg)

        return self


    def _parseDataElementPresenceMap(self, depm):
        """
        Convert concatenated bin tags into a list of string tag.

        >>> from pypassport.doc9303.datagroup import DataGroup, DataGroupFile
        >>> from pypassport.hexfunctions import *
        >>> header = None
        >>> body = hexRepToBin("5C0A5F0E5F115F425F125F13")
        >>> dgf = DataGroupFile()
        >>> dg = DataGroup(dgf)
        >>> res = dg._parseDataElementPresenceMap(body[0x02:])
        >>> res
        ['5F0E', '5F11', '5F42', '5F12', '5F13']

        @param depm: The data element presence map
        @type depm: A binary string
        @return: A list with the tags found in the data element presence map.
        """
        byteNb = self._byteNb
        data = self._data

        self._byteNb = 0
        self._data = depm
        tags = []

        while self._byteNb < len(depm):
            tag = self._getTag()
            tags.append(tag)

        self._byteNb = byteNb
        self._data = data

        return tags
    
    def _getValue(self):
        length = self._getLength()
        value = self._data[self._byteNb:self._byteNb + length]
        self._byteNb += length
        return value
    
    def _getLength(self):
        (length, offset) = asn1Length(self._data[self._byteNb:])
        self._byteNb += offset
        return length