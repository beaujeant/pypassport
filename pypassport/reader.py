import os
import sys
import time
import logging

from smartcard.util import *
from pypassport import hexfunctions
from pypassport.apdu import CommandAPDU, ResponseAPDU
from pypassport.singleton import Singleton
from pypassport.doc9303 import converter

if sys.platform == 'win32':
    f = os.popen("net start scardsvr", "r")
    res = f.read()
    f.close()


class ReaderException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class TimeOutException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class apduWrapper:
    def __init__(self, data):
        self._apdu = data


    def getHexListAPDU(self):
        return self._apdu


class Reader():

    def __init__(self):
        self.readerName = None
        self.readerNum = None


    def connect(self, readerNum=None):
        """
        If there is some reader connected to the computer, we have to specify to which one we want to connect.

        @param readerNum: The reader number.
        @type readerNum: An integer.
        """
        raise Exception("Should be implemented")


    def transmit(self, APDU):
        """
        The method sends the apdu to the reader and returns the ICC answer

        @param APDU: The apdu to transmit to the reader
        @type APDU: A commandAPDU object
        @return: A resultAPDU object with the ICC answer.
        """
        raise Exception("Should be implemented")


    def disconnect(self):
        """
        To release the reader.
        """
        raise Exception("Should be implemented")


    def getReaderList(self):
        raise Exception("Should be implemented")


class DumpReader(Reader):
    """
    The class adds two properties:
    format: the file naming convention
    ext: the file extension
    """

    def __init__(self):
        self._file = None
        self.format = "GRT"
        self.ext = ".bin"
        super(Reader, self).__init__()


    def connect(self, path):
        if os.path.isdir(str(path)):
            self.readerNum = path + os.sep
            return True
        return False


    def transmit(self, apdu):
        if apdu.ins == "A4":
            if apdu.data == "A0000002471001":
                #Passport AID
                pass
            else:
                #SelectFile
                try:
                    if self._file:
                        self._file.close()
                    self._file = open(self.readerNum + converter.to(self.format, apdu.data) + self.ext, "rb")
                except Exception as msg:
                    return ResponseAPDU(str(msg), 0x6A, 0x82)
            return ResponseAPDU("", 0x90, 0x00)

        elif apdu.ins == "B0":
            #ReadBinary
            try:
                offset = hexfunctions.hexRepToHex(apdu.p1 + apdu.p2)
                self._file.seek(offset)
                res = self._file.read(hexfunctions.hexRepToHex(apdu.le))
                return ResponseAPDU(res, 0x90, 0x00)
            except Exception as msg:
                return ResponseAPDU(str(msg), 0x6A, 0x88)

        #Function not supported
        return ResponseAPDU("", 0x6A, 0x81)


    def disconnect(self):
        if self._file:
            self._file.close()


    def getReaderList(self):
        return ["Simulator"]


class PcscReader(Reader):

    def __init__(self):
        self.importSC()
        self._pcsc_connection = None
        self.readerName = None
        self.readerNum = None
        super(Reader, self).__init__()


    def importSC(self):
        try:
            import smartcard
            self.sc = smartcard
        except Exception:
            if sys.platform == 'darwin':
                msg = "The smart card service/daemon is not started.\n"
                msg += "Please insert a reader and restart the application."
            elif sys.platform == 'win32':
                msg = "The smart card service is not started.\n"
                msg += "Please execute the following command in your os shell: \n"
                msg += "Windows: net start scardsvr"
            else:
                msg = "The smart card daemon is not started.\n"
                msg += "Please execute the following command in your os shell: \n"
                msg += "Linux: sudo /etc/init.d/pcscd start"
            raise ReaderException(msg)


    def connect(self, reader_index=None):
        reader_list = self.getReaderList()
        if reader_index:
            reader_index = int(reader_index)
            if reader_index in range(len(reader_list)):
                self.reader = self.getReaderList()[reader_index]
                try:
                    self._pcsc_connection = self.reader.createConnection()
                    self._pcsc_connection.connect(self.sc.scard.SCARD_PCI_T0)
                    return True
                except self.sc.Exceptions.NoCardException:
                    return False
            else:
                raise ReaderException("The reader number is invalid")
        else:
            for reader in reader_list:
                try:
                    self._pcsc_connection = reader.createConnection()
                    self._pcsc_connection.connect(self.sc.scard.SCARD_PCI_T0)
                    self.reader = reader
                    return True
                except self.sc.Exceptions.NoCardException:
                    pass
            return False



    def disconnect(self):
        self._pcsc_connection.disconnect()


    def transmit(self, APDU):
        try:
            res = self._pcsc_connection.transmit(APDU.getHexListAPDU())
            rep = ResponseAPDU(hexfunctions.hexListToBin(res[0]), res[1], res[2])
            return rep
        except self.sc.Exceptions.CardConnectionException as msg:
            raise ReaderException(msg)


    def getReaderList(self):
        readers = list()
        try:
            readers = self.sc.System.readers()
        except Exception as e:
            logging.debug("Type: {}\nMessage: {}".format(type(e), e))
        return readers



class Acr122Reader(PcscReader):

    Control = {
        "AntennaPowerOff": [0x01, 0x00],
        "AntennaPowerOn": [0x01, 0x01],
        "ResetTimer": [0x05, 0x00, 0x00, 0x00]
    }

    Polling = {
        "ISO14443A": [0x01, 0x00]
    }

    Speed = {
        "212 kbps": [0x01, 0x01, 0x01],
        "424 kbps": [0x01, 0x02, 0x02]
    }

    Pseudo_APDU = {
        "DirectTransmit": [0xFF, 0x00, 0x00, 0x00],
        "GetResponse": [0xFF, 0xC0, 0x00, 0x00]
    }

    PN532_Cmd = {
        "InListPassiveTarget": [0xD4, 0x4A, 0x01, 0x01],
        "InDataExchange": [0xD4, 0x40, 0x01],
        "Control": [0xD4, 0x32],
        "Polling": [0xD4, 0x4A],
        # Change to Baud Rate 424 kbps
        "Speed": [0xD4, 0x4E]
    }

    Errors = {
        0x61: 'SW2 Bytes left to read',
        0x63: {
            0x00: 'The operation failed.',
            0x01: 'The PN532 does not respond.',
            0x27: 'Command not acceptable in context of PN532',
            #0x27:'The checksum of the Contactless Response is wrong.',
            0x7F: 'The PNNAME = "GENERIC PC/SC"532_Contactless Command is wrong.'
        },
        0x90: 'Success'
    }


    def connect(self, rn=None):
        if super(Acr122Reader, self).connect(rn):
            self.transmit(apduWrapper(Acr122Reader.Control["AntennaPowerOff"]), "Control")
            self.transmit(apduWrapper(Acr122Reader.Control["AntennaPowerOn"]), "Control")
            self.transmit(apduWrapper(Acr122Reader.Control["ResetTimer"]), "Control")
            self.transmit(apduWrapper(Acr122Reader.Polling["ISO14443A"]), "Polling")
            self.transmit(apduWrapper(Acr122Reader.Speed["424 kbps"]), "Speed")
            return True


    def transmit(self, APDU, PN532_Cmd="InDataExchange"):
        # Send Command
        hexListAPDU = APDU.getHexListAPDU()
        wrappedApdu = Acr122Reader.Pseudo_APDU["DirectTransmit"] + [len(Acr122Reader.PN532_Cmd[PN532_Cmd]) + len(hexListAPDU)] + Acr122Reader.PN532_Cmd[PN532_Cmd] + hexListAPDU

        # Check if there is data to read

        try:
            res = self._pcsc_connection.transmit(wrappedApdu)

            # Handle "SW2 Bytes left to read" error
            if res[1] == 0x61:
                wrappedApdu = Acr122Reader.Pseudo_APDU["GetResponse"] + [res[2]]
                res = self._pcsc_connection.transmit(wrappedApdu)
                if res[1] == 0x90:
                    res[0], res[1], res[2] = self._removePN532Header(res[0])

            rep = ResponseAPDU(hexfunctions.hexListToBin(res[0]), res[1], res[2])
            print(rep)
            return rep
        except self.sc.Exceptions.CardConnectionException:
            try:
                error_message = Acr122Reader.Errors[res[1]][res[2]]
            except Exception:
                error_message = "Unknown error"

            raise ReaderException("Unexpected APDU response: Data:\"{}\" SW1:{} SW2:{} ({})".format(res[0], hex(res[1]), hex(res[2]), error_message))
        except Exception as e:
            print("ERROR: {}".format(e))

        """
        try:
            error_message = Acr122Reader.Errors[res[1]][res[2]]
        except Exception:
            error_message = "Unknown error"

        raise ReaderException("Unexpected APDU response: Data:\"{}\" SW1:{} SW2:{} ({})".format(res[0], hex(res[1]), hex(res[2]), error_message))

        except KeyError:
            #Unknown error from acr122
            #Checked in the upper layer
            data, sw1, sw2 = self._removePN532Header(res[0])
            return ResponseAPDU(hexfunctions.hexListToBin(data), sw1, sw2)
        """


    def _removePN532Header(self, data):
        # direct transmit or speed change response -- 3 bytes of header
        if (data[0:2] == [0xD5, 0x41] or data[0:2] == [0xD5, 0x4F]) and data[2] == 0x00:
            return data[3:-2], data[-2], data[-1]
        # otherwise 2 byte of header
        return data[2:-2], data[-2], data[-1]



class ReaderManager(Singleton):

    def __init__(self):
        self.drivers = {
            "DumpReader": DumpReader,
            "PcscReader": PcscReader,
            "Acr122Reader": Acr122Reader
        }

        self._blackList = [
            #"Acr122Reader",
            "DumpReader"
        ]


    def getDriverInstance(self, driver="PcscReader"):
        """
        Create a new instance of the specified driver
        """
        try:
            return self.drivers[driver]()
        except KeyError:
            raise ReaderException("Unsupported reader: " + str(reader))


    def getDriverList(self):
        driver_list = list()
        for driver in self.drivers:
            if not self._isBLacklisted(driver):
                driver_list.append(self.getDriverInstance(driver))
        return driver_list


    def getReaderList(self):
        reader_list = list()
        for driver in self.drivers:
            if not self._isBLacklisted(driver):
                reader_list += self.getDriverInstance(driver).getReaderList()
        return reader_list


    def _isBLacklisted(self, driver):
        if driver in self._blackList:
            return True
        else:
            return False


    def _autoDetect(self):
        """
        Pool every connected reader with every driver available by the factory.
        When a couple (driver, num reader) can select the AID, we have a good reader!
        Return a couple (reader object, reader number, reader name)
        """
        for driver in self.getDriverList():

            if driver.connect():
                try:
                    # Select the LDS DF by AID. If this fails, the MRTD isn't equipped with an ICAO LDS compliant ICC.
                    # Otherwise the correct response will be '90 00'.
                    res = driver.transmit(CommandAPDU("00", "A4", "04", "0C", "07", "A0000002471001"))
                    if res.sw1 == 0x90 and res.sw2 == 0x00:
                        logging.debug("Passport found: {}".format(driver.__class__.__name__))
                        return driver
                except Exception as e:
                    logging.error("An error occured while trying to detect a passport: {}".format(e))
                    driver.disconnect()
        return None


    def getReader(self, timeout=5, driver=None, readerNum=None):

        """
        Wait until a card is put on a reader.
        After I{timeout} seconds, the loop is broken and an TimeOutException is raised
        If I{driver} and I{readerNum} are let to none, the wait for loop will poll on every reader with every driver until a match is found.
        If I{driver} and I{readerNum} are both set, the loop will poll on the specified reader with the specified driver.
        By default, the time-out is set to 15 seconds.

        @param timeout: The timeout in second the loop wait for a card before being interrupted.
        @type timeout: Integer
        @param driver: The driver to use during the polling
        @type driver: A class inheriting from Reader
        @param readerNum: The reader to poll on
        @type readerNum: Integer

        @raise TimeOutException: Is the time-out expires, the exception is raised.

        """
        cpt = 0
        wait = 0.5

        logging.debug("Scanning for available reader")

        if driver is None and readerNum is None:
            reader = None
            while not reader and cpt < timeout:
                reader = self._autoDetect()
                time.sleep(wait)
                cpt += wait
            if cpt == timeout:
                raise TimeOutException("Time-out")
            return reader

        else:
            reader = self.getDriverInstance(driver)
            while not reader.connect(readerNum) and cpt < timeout:
                time.sleep(wait)
                cpt += wait
            if cpt == timeout:
                raise TimeOutException("Time-out")
            return reader
