_Table = {
    "DISP": ["Common", "DG 1", "DG 2", "DG 3", "DG 4", "DG 5", "DG 6", "DG 7", "DG 8", "DG 9", "DG 10", "DG 11", "DG 12", "DG 13", "DG 14", "DG 15", "DG 16", "Security Data", "ATR/INFO", "DIR", "CardAccess", "CardSecurity"],
    "DG": ["COM", "DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7", "DG8", "DG9", "DG10", "DG11", "DG12", "DG13", "DG14", "DG15", "DG16", "SecurityData", "ATR/INFO", "DIR", "CardAccess", "CardSecurity"],
    "EF": ["EF.COM", "EF.DG1", "EF.DG2", "EF.DG3", "EF.DG4", "EF.DG5", "EF.DG6", "EF.DG7", "EF.DG8", "EF.DG9", "EF.DG10", "EF.DG11", "EF.DG12", "EF.DG13", "EF.DG14", "EF.DG15", "EF.DG16", "EF.SOD", "EF.ATR", "EF.DIR", "EF.CardAccess", "CardSecurity"],
    "SFID": ["1E", "81", "82", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10", "1D", "FF", "FF", "9C", "1D"],
    "FID": ["011E", "0101", "0102", "0103", "0104", "0105", "0106", "0107", "0108", "0109", "010A", "010B", "010C", "010D", "010E", "010F", "0110", "011D", "2F01", "2F00", "011C", "011D"],
    "TAG": ["60", "61", "75", "63", "76", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "77", "ATR/INFO", "DIR", "42", "77"],
    "CLASS": ["Common", "DataGroup1", "DataGroup2", "DataGroup3", "DataGroup4", "DataGroup5", "DataGroup6", "DataGroup7", "DataGroup8", "DataGroup9", "DataGroup10", "DataGroup11", "DataGroup12", "DataGroup13", "DataGroup14", "DataGroup15", "DataGroup16", "SOD", "ATR", "DIR", "CardAccess", "CardSecurity"],
    "OTHER": ["EF", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "SOD", "ATR/INFO", "DIR", "CardAccess", "CardSecurity"],
    "ORDER": ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21"],
    "GRT": ["EF_COM", "Datagroup1", "Datagroup2", "Datagroup3", "Datagroup4", "Datagroup5", "Datagroup6", "Datagroup7", "Datagroup8", "Datagroup9", "Datagroup10", "Datagroup11", "Datagroup12", "Datagroup13", "Datagroup14", "Datagroup15", "Datagroup16", "EF_SOD", "EF_ATR_INFO", "EF_DIR", "CardAccess", "CardSecurity"],
    "INT": [0x60, 0x61, 0x75, 0x63, 0x76, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x77, 0xff, 0xff, 0xff, 0xff]
}


def toDISP(data):
    """
    Transform the data value to its value to display
    """
    return to("DISP", data)


def toDG(data):
    """
    Transform the data value to its DG representation
    """
    return to("DG", data)


def toEF(data):
    """
    Transform the data value to its EF representation
    """
    return to("EF", data)



def toSFID(data):
    """
    Transform the data value to its Short File Identification representation
    """
    return to("SFID", data)


def toFID(data):
    """
    Transform the data value to its FID representation
    """
    return to("FID", data)


def toTAG(data):
    """
    Transform the data value to its TAG representation
    """
    return to("TAG", data)


def toClass(data):
    """
    Return the class linked to the parameter value
    """
    return to("CLASS", data)


def toOther(data):
    """
    Transform the data value to its OTHER representation
    """
    return to("OTHER", data)


def toOrder(data):
    """
    Transform the data value to its ORDER representation (0 to 17)
    """
    return to("ORDER", data)


def toGRT(data):
    """
    Transform the data value to its GoldenReaderTool representation
    """
    return to("GRT", data)


def toINT(data):
    """
    Transform the data value to its GoldenReaderTool representation
    """
    return to("INT", data)


def to(table, data):
    """
    Return the element value from the specified list at the found possition
    """
    index = _getIndex(data)
    return _Table[table][index]


def _getIndex(data):
    """
    Look for the corresponding data value in every list of the _Table dictionary.
    If the data value is found, its position is returned.
    """
    for line in _Table.values():
        for index, value in enumerate(line):
            if str(value).upper() == str(data).upper():
                return index
    raise KeyError("Invalid Data Group: " + str(data))
