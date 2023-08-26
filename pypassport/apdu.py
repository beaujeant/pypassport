from pypassport import hexfunctions


class CommandAPDU(object):
    def __init__(self, cla, ins, p1, p2, lc="", data="", le=""):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2

        self.lc = lc
        self.data = data
        self.le = le

    def getCla(self):
        return self.__cla


    def setCla(self, value):
        self.__cla = value


    def delCla(self):
        del self.__cla


    def getIns(self):
        return self.__ins


    def setIns(self, value):
        self.__ins = value


    def delIns(self):
        del self.__ins


    def getP1(self):
        return self.__p1


    def setP1(self, value):
        self.__p1 = value


    def delP1(self):
        del self.__p1


    def getP2(self):
        return self.__p2


    def setP2(self, value):
        self.__p2 = value


    def delP2(self):
        del self.__p2


    def getLc(self):
        return self.__lc


    def setLc(self, value):
        self.__lc = value


    def delLc(self):
        del self.__lc


    def getData(self):
        return self.__data


    def setData(self, value):
        self.__data = value


    def delData(self):
        del self.__data


    def getLe(self):
        return self.__le


    def setLe(self, value):
        self.__le = value


    def delLe(self):
        del self.__le

    def getBinAPDU(self):
        return hexfunctions.hexRepToBin(self.getHexRepAPDU())

    def getHexRepAPDU(self):
        return self.cla + self.ins + self.p1 + self.p2 + self.lc + self.data + self.le

    def getHexListAPDU(self):
        return hexfunctions.hexRepToList(self.getHexRepAPDU())

    def __str__(self):
        return "> " + self.cla + " " + self.ins + " " + self.p1 + " " + self.p2 + " " + self.lc + " [" + self.data + "] " + self.le

    cla = property(getCla, setCla, delCla, "Cla's Docstring")

    ins = property(getIns, setIns, delIns, "Ins's Docstring")

    p1 = property(getP1, setP1, delP1, "P1's Docstring")

    p2 = property(getP2, setP2, delP2, "P2's Docstring")

    lc = property(getLc, setLc, delLc, "Lc's Docstring")

    data = property(getData, setData, delData, "Data's Docstring")

    le = property(getLe, setLe, delLe, "Le's Docstring")


class ResponseAPDU(object):
    def __init__(self, res, sw1, sw2):
        self.__res = res
        self.__sw1 = sw1
        self.__sw2 = sw2

    def getRes(self):
        return self.__res

    def setRes(self, value):
        self.__res = value

    def getSW1(self):
        return self.__sw1

    def setSW1(self, value):
        self.__sw1 = value

    def getSW2(self):
        return self.__sw2

    def setSW2(self, value):
        self.__sw2 = value

    def getHexListAPDU(self):
        return self.res + [self.sw1] + [self.sw2]

    def getBinAPDU(self):
        return self.res + hexfunctions.hexListToBin([self.sw1] + [self.sw2])

    def getHexRepAPDU(self):
        return hexfunctions.binToHexRep(self.res) + hexfunctions.hexToHexRep(self.sw1) + hexfunctions.hexToHexRep(self.sw2)

    def __str__(self):
        return "< [{}] {} {}".format(hexfunctions.binToHexRep(self.res), hexfunctions.hexToHexRep(self.sw1), hexfunctions.hexToHexRep(self.sw2))

    res = property(getRes, setRes)

    sw1 = property(getSW1, setSW1)

    sw2 = property(getSW2, setSW2)
