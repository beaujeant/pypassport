from pypassport.asn1 import asn1Exception, asn1Length


class TLVParserException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class TLVParser(dict):
    def __init__(self, data):
        self._data = data
        self._byteNb = 0

    def _getTag(self):
        raise Exception("Should be implemented")

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
        except asn1Exception as exc:
            raise TLVParserException(exc[0])

        return self
