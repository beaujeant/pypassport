import logging
from pypassport import reader
from pypassport.utils import toHexString, toBytes, toHexString, toList


class APDUCommand():

    Instructions = {
        "VERIFY": 0x20,
        "CHANGE REFERENCE DATA": 0x24,
        "RESET RETRY COUNTER": 0x2c,
        "GET CHALLENGE": 0x84,
        "INTERNAL AUTHENTICATE": 0x88,
        "EXTERNAL AUTHENTICATE": 0x82,
        "SELECT FILE": 0xa4,
        "READ BINARY": 0xb0,
        "READ RECORDS": 0xb2,
        "UPDATE BINARY": 0xd6,
        "ERASE BINARY": 0xda,
        "ERASE RECORDS": 0xdc,
        "UPDATE RECORDS": 0xdc,
        "APPEND RECORD": 0xe2
    }

    def __init__(self, cla="00", ins="00", p1="00", p2="00", lc="", data="", le=""):
        if isinstance(cla, str):
            self.cla = cla[:2]
        elif isinstance(cla, bytes):
            self.cla = toHexString(cla)[:2]
        elif isinstance(cla, int):
            self.cla = toHexString([cla])[:2]
        else:
            self.cla="00"

        if isinstance(ins, str):
            self.ins = ins[:2]
        elif isinstance(ins, bytes):
            self.ins = toHexString(ins)[:2]
        elif isinstance(ins, int):
            self.ins = toHexString([ins])[:2]
        else:
            self.ins="00"

        if isinstance(p1, str):
            self.p1 = p1[:2]
        elif isinstance(p1, bytes):
            self.p1 = toHexString(p1)[:2]
        elif isinstance(p1, int):
            self.p1 = toHexString([p1])[:2]
        else:
            self.p1="00"

        if isinstance(p2, str):
            self.p2 = p2[:2]
        elif isinstance(p2, bytes):
            self.p2 = toHexString(p2)[:2]
        elif isinstance(cla, int):
            self.p2 = toHexString([p2])[:2]
        else:
            self.p2="00"

        if (isinstance(data, str) and data) and (isinstance(lc, str) and not lc):
            self.lc = "%02x" % (len(data) // 2)
        elif (isinstance(data, bytes) and data) and (isinstance(lc, str) and not lc):
            self.lc = "%02x" % len(data)
        elif isinstance(lc, str) and lc:
            self.lc = lc[:2]
        elif isinstance(lc, bytes) and lc:
            self.lc = toHexString(lc)[:2]
        elif isinstance(lc, int):
            self.lc = toHexString([lc])[:2]
        else:
            self.lc = ""

        if isinstance(data, str):
            self.data = data
        elif isinstance(data, bytes):
            self.data = toHexString(data)
        else:
            self.data = ""

        if isinstance(le, str):
            self.le = le
        elif isinstance(le, bytes):
            self.le = toHexString(le)
        elif isinstance(le, int):
            self.le = toHexString([le])
        else:
            self.le = ""

    def raw(self):
        return toList(str(self))
    
    def __str__(self):
        return self.cla + self.ins + self.p1 + self.p2 + self.lc + self.data + self.le
    
    def __repr__(self):
        output = f"Command APDU [Class: {self.cla} Instruction: {self.ins} Parameter 1: {self.p1} Parameter 2: {self.p2}]"
        if self.data:
            output += f" [Data: {self.data} (len {self.lc})]"
        if self.le:
            output += f" [Expected Response Length: {self.le}]"
        return output


class APDUResponse():

    Status = {
        0x61: 'SW2 indicates the number of response bytes still available',
        0x62: {
            0x00: 'No information given',
            0x81: 'Part of returned data may be corrupted',
            0x82: 'End of file/record reached before reading Le bytes',
            0x83: 'Selected file invalidated',
            0x84: 'FCI not formatted according to ISO7816-4 section 5.1.5'
        },
        0x63: {
            0x00: 'No information given',
            0x81: 'File filled up by the last write',
            0x82: 'Card Key not supported',
            0x83: 'Reader Key not supported',
            0x84: 'Plain transmission not supported',
            0x85: 'Secured Transmission not supported',
            0x86: 'Volatile memory not available',
            0x87: 'Non Volatile memory not available',
            0x88: 'Key number not valid',
            0x89: 'Key length is not correct',
            0x0C: 'Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)'
        },
        0x64: 'State of non-volatile memory unchanged (SW2=00, other values are RFU)',
        0x65: {
            0x00: 'No information given',
            0x81: 'Memory failure'
        },
        0x66: 'Reserved for security-related issues (not defined in this part of ISO/IEC 7816)',
        0x67: {
            0x00: 'Wrong length'
        },
        0x68: {
            0x00: 'No information given',
            0x81: 'Logical channel not supported',
            0x82: 'Secure messaging not supported'
        },
        0x69: {
            0x00: 'No information given',
            0x81: 'Command incompatible with file structure',
            0x82: 'Security status not satisfied',
            0x83: 'Authentication method blocked',
            0x84: 'Referenced data invalidated',
            0x85: 'Conditions of use not satisfied',
            0x86: 'Command not allowed (no current EF)',
            0x87: 'Expected SM data objects missing',
            0x88: 'SM data objects incorrect'
        },
        0x6A: {
            0x00: 'No information given',
            0x80: 'Incorrect parameters in the data field',
            0x81: 'Function not supported',
            0x82: 'File not found',
            0x83: 'Record not found',
            0x84: 'Not enough memory space in the file',
            0x85: 'Lc inconsistent with TLV structure',
            0x86: 'Incorrect parameters P1-P2',
            0x87: 'Lc inconsistent with P1-P2',
            0x88: 'Referenced data not found'
        },
        0x6B: {
            0x00: 'Wrong parameter(s) P1-P2'
        },
        0x6C: 'Wrong length Le: SW2 indicates the exact length',
        0x6D: {
            0x00: 'Instruction code not supported or invalid'
        },
        0x6E: {
            0x00: 'No precise diagnosis'
        },
        0x90: {
            0x00: 'Success'
        }
    }

    def __init__(self, data, sw1, sw2):
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2

        try:
            self.status = self.Status[sw1][sw2]
        except IndexError:
            self.status = "Unknown error"

    def raw(self):
        return bytes(list(self.data) + [self.sw1] + [self.sw2])

    def __str__(self):
        return toHexString(list(str(self)))

    def __repr__(self):
        return f"APDU Response [Data: {toHexString(self.data)}] [Status Word 1: {hex(self.sw1)}] [Status Word 2: {hex(self.sw2)}] ({self.status})"


class ISO7816Exception(Exception):
    def __init__(self, data, sw1=None, sw2=None):
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
        Exception.__init__(self, data, sw1, sw2)


class ISO7816():

    def __init__(self, reader):
        self._reader = reader
        self.ciphering = False

    def transmit(self, toSend, logMsg=None):
        """
        @param toSend: The command to transmit.
        @type toSend: An APDUCommand object.
        @param logMsg: A log message associated to the transmit.
        @type logMsg: A string.
        @return: The result field of the responseAPDU object

        The P1 and P2 fields are checked after each transmit.
        If they don't mean success, the appropriate error string is retrieved
        from the Error dictionary and an ISO7816Exception is raised.
        The ISO7816Exception is composed of three fields: ('error message', p1, p2)
        """

        log_enc = ""
        if logMsg:
            logging.debug(f"Transmit APDU: {logMsg}")

        if self.ciphering:
            log_enc = "Encrypted "
            toSend = self.ciphering.protect(toSend)

        logging.debug(f"> {log_enc}{repr(toSend)}")

        data, sw1, sw2 = self._reader.transmit(toSend.raw())
        response = APDUResponse(data, sw1, sw2)

        if self.ciphering:
            response = self.ciphering.unprotect(response)

        logging.debug(f"< {log_enc}{repr(response)})")

        if response.status == "Success":
            return bytes(response.data)
        else:
            logging.debug(f"APDU Response Error: {response.status} [{hex(response.sw1)}] [{hex(response.sw2)}]")
            raise ISO7816Exception(response.status, response.sw1, response.sw2)

    def rstConnectionRaw(self):
        reader_name = self._reader.getReader()
        try:
            self._reader.disconnect()
            self._reader = reader.getReader(reader_name)
            self._reader.connect()
            self.ciphering = False
            return
        except Exception as e:
            raise ISO7816Exception(f"An error occured while resetting the connection: {e}")

    def rstConnection(self):
        try:
            self.rstConnectionRaw()
            self.selectDedicatedFile("A0000002471001")
        except Exception as e:
            raise ISO7816Exception(f"An error occured while resetting the connection: {e}")

    def selectFile(self, p1, p2, file):
        toSend = APDUCommand("00", "A4", p1, p2, data=file)
        return self.transmit(toSend, f"Select File {file}")

    def selectElementaryFile(self, file):
        return self.selectFile("02", "0C", file)

    def selectDedicatedFile(self, file):
        return self.selectFile("04", "0C", file)

    def readBinary(self, offset, nbOfByte):
        os = "%04x" % int(offset)
        toSend = APDUCommand("00", "B0", os[0:2], os[2:4], le=toHexString([nbOfByte]))
        return self.transmit(toSend, f"Reading binary at offset {offset} - expecting {nbOfByte} bytes")

    def readBinarySF(self, shortFileID, offset, nbOfByte):
        os = "%02x" % int(offset)
        toSend = APDUCommand("00", "B0", shortFileID, os, le=toHexString([nbOfByte]))
        return self.transmit(toSend, f"Reading binary with SFID {shortFileID} at offset {offset} - expecting {nbOfByte} bytes")

    def updateBinary(self, offset, data):
        os = "%04x" % int(offset)
        toSend = APDUCommand("00", "D6", os[0:2], os[2:4], data=data)
        return self.transmit(toSend, "Update Binary")

    def getUID(self):
        toSend = APDUCommand("FF", "CA", "00", "00", le="00")
        return self.transmit(toSend, "Get UID")

    def internalAuthentication(self, rnd_ifd):
        toSend = APDUCommand("00", "88", "00", "00", data=rnd_ifd, le="00")
        return self.transmit(toSend, "Internal Authentication")

    def getChallenge(self):
        toSend = APDUCommand("00", "84", "00", "00", le="08")
        return self.transmit(toSend, "Get Challenge")

    def mutualAuthentication(self, eifd_mifd):
        toSend = APDUCommand("00", "82", "00", "00", data=eifd_mifd, le="28")
        return self.transmit(toSend, "Mutual Authentication")

    def mseSetAt(self, pace_oid, reference, domain_params=b"", chat=b""):
        self.ciphering = False
        pace_oid = bytes([0x80, len(pace_oid)]) + pace_oid
        reference = bytes([0x83, len(reference)]) + reference
        if chat:
            chat = bytes([0x7F, 0x4C, len(chat)]) + chat
        if domain_params:
            domain_params = bytes([0x84, len(domain_params)]) + domain_params
        payload = pace_oid + reference + chat + domain_params
        toSend = APDUCommand("00", "22", "C1", "A4", data=payload)
        return self.transmit(toSend, "MSE:Set At")

    def generalAuthenticate(self):
        toSend = APDUCommand("10", "86", "00", "00", data="7C00", le="00")
        return self.transmit(toSend, "General Authenticate")