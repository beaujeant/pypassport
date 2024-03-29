import logging

from pypassport import hexfunctions
from pypassport import apdu


class Iso7816Exception(Exception):
    def __init__(self, description, sw1=None, sw2=None):
        self.description = description
        self.sw1 = sw1
        self.sw2 = sw2
        Exception.__init__(self, description, sw1, sw2)


class Iso7816():

    Errors = {
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


    def __init__(self, reader):
        self._reader = reader
        self._ciphering = False


    def rstConnection(self):
        rn = self._reader.readerNum
        try:
            self._reader.disconnect()
            self._reader.connect(rn)
            self.setCiphering(False)
            self.selectFile("04", "0C", "A0000002471001")
        except Exception as e:
            raise Iso7816Exception("An error occured while resetting the connection: {}".format(e))


    def getTypeReader(self):
        return type(self._reader)


    def transmitRaw(self, toSend):
        try:
            if self._ciphering:
                toSend = self._ciphering.protect(toSend)
            res = self._reader.transmit(toSend)
            if self._ciphering:
                res = self._ciphering.unprotect(res)
            return res
        except KeyError:
            raise Iso7816Exception("Unknown error", res.sw1, res.sw2)

    def rstConnectionRaw(self):
        rn = self._reader.readerNum
        try:
            self._reader.disconnect()
            self._reader.connect(rn)
            self.setCiphering()
        except Exception:
            raise Iso7816Exception("An error occured while resetting the connection")


    def transmit(self, toSend, logMsg=None):
        """
        @param toSend: The command to transmit.
        @type toSend: A commandAPDU object.
        @param logMsg: A log message associated to the transmit.
        @type logMsg: A string.
        @return: The result field of the responseAPDU object

        The P1 and P2 fields are checked after each transmit.
        If they don't mean success, the appropriate error string is retrieved
        from the Error dictionary and an APDUException is raised.
        The Iso7816Exception is composed of three fields: ('error message', p1, p2)

        To access these fields when the exception is raised,
        access the APDUException object like a list::

            try:
                x.apduTransmit(commandAPDU(..))
            except Iso7816Exception, exc:
                print "error: " + exc[0]
                print "(pw1, pw2) + str( (exc[1], exc[2]) )
        """
        try:
            logging.debug(logMsg)

            logging.debug("> Command APDU [Class: {}] [Instruction: {}] [Parameter 1: {}] [Parameter 2: {}] [Data: {}] [Expected Response Length: {}]".format(toSend.cla, toSend.ins, toSend.p1, toSend.p2, toSend.lc, toSend.data, toSend.le))

            if self._ciphering:
                toSend = self._ciphering.protect(toSend)
                logging.debug("> Encrypted Command APDU [Class: {}] [Instruction: {}] [Parameter 1: {}] [Parameter 2: {}] [Data: {}] [Expected Response Length: {}]".format(toSend.cla, toSend.ins, toSend.p1, toSend.p2, toSend.lc, toSend.data, toSend.le))

            res = self._reader.transmit(toSend)
            msg = Iso7816.Errors[res.sw1][res.sw2]

            if self._ciphering:
                logging.debug("< Encrypted Response APDU [Response: {}] [Status Word 1: {}] [Status Word 2: {}] ({})".format(hexfunctions.binToHexRep(res.res), hex(res.sw1), hex(res.sw2), msg))
                res = self._ciphering.unprotect(res)

            logging.debug("< Response APDU [Response: {}] [Status Word 1: {}] [Status Word 2: {}] ({})".format(hexfunctions.binToHexRep(res.res), hex(res.sw1), hex(res.sw2), msg))

            if msg == "Success":
                return res.res
            else:
                raise Iso7816Exception(msg, res.sw1, res.sw2)
        except KeyError:
            raise Iso7816Exception("Unknown error code", res.sw1, res.sw2)

    def setCiphering(self, c=False):
        self._ciphering = c

    def selectFile(self, p1, p2, file="", cla="00", ins="A4"):
        lc = hexfunctions.hexToHexRep(len(file) / 2)
        toSend = apdu.CommandAPDU(cla, ins, p1, p2, lc, file, "")
        return self.transmit(toSend, "Select File")

    def readBinary(self, offset, nbOfByte):
        os = "%04x" % int(offset)
        toSend = apdu.CommandAPDU("00", "B0", os[0:2], os[2:4], "", "", hexfunctions.hexToHexRep(nbOfByte))
        return self.transmit(toSend, "Read Binary")

    def updateBinary(self, offset, data, cla="00", ins="D6"):
        os = "%04x" % int(offset)
        data = hexfunctions.binToHexRep(data)
        lc = hexfunctions.hexToHexRep(len(data) / 2)
        toSend = apdu.CommandAPDU(cla, ins, os[0:2], os[2:4], lc, data, "")
        return self.transmit(toSend, "Update Binary")

    def getChallenge(self):
        toSend = apdu.CommandAPDU("00", "84", "00", "00", "", "", "08")
        return self.transmit(toSend, "Get Challenge")

    def getUID(self):
        toSend = apdu.CommandAPDU("FF", "CA", "00", "00", "", "", "00")
        return self.transmit(toSend, "Get UID")

    def internalAuthentication(self, rnd_ifd):
        data = hexfunctions.binToHexRep(rnd_ifd)
        lc = hexfunctions.hexToHexRep(len(data) / 2)
        toSend = apdu.CommandAPDU("00", "88", "00", "00", lc, data, "00")
        res = self.transmit(toSend, "Internal Authentication")
        return res
