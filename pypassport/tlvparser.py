from pypassport.asn1 import asn1Exception, asn1Length
from pypassport import hexfunctions

class TLVParserException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class TLVParser(dict):
    def __init__(self, data=None):
        self._data = data
        self._byteNb = 0

    def _getTag(self):
        if (hexfunctions.binToHex(self._data[self._byteNb]) & 0x0F) == 0x0F:
            tag = hexfunctions.binToHexRep(self._data[self._byteNb:self._byteNb + 2]).upper()
            self._byteNb += 2
        else:
            tag = hexfunctions.binToHexRep(self._data[self._byteNb]).upper()
            self._byteNb += 1
        return tag

    def _getLength(self):
        (length, offset) = asn1Length(self._data[self._byteNb:])
        self._byteNb += offset
        return length

    def _getValue(self):
        length = self._getLength()
        value = self._data[self._byteNb:self._byteNb + length]
        self._byteNb += length
        return value

    def parse(self):
        self._byteNb = 0
        self.clear()
        try:
            while self._byteNb < len(self._data) - 1:
                tag = self._getTag()
                value = self._getValue()
                self[tag] = value
        except asn1Exception as e:
            raise TLVParserException(e[0])

        return self
