import logging
from smartcard.System import readers
from smartcard.pcsc import PCSCExceptions

class ReaderException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


def listReaders():
    try:
        list_readers = readers()
        logging.info(f"Available reader(s): {str(list_readers)}")
        return list_readers
    except PCSCExceptions.EstablishContextException:
        logging.error(f"PC/SC Smart Card service not available")
        return None

def getReader(index=None):
    list_readers = listReaders()
    if list_readers:
        if isinstance(index, int):
            try:
                logging.info(f"Reader {str(list_readers[index])} selected")
                return list_readers[index].createConnection()
            except IndexError:
                pass
        elif isinstance(index, str):
            for i in range(len(list_readers)):
                if str(list_readers[i]) == index:
                    logging.info(f"Reader {str(list_readers[i])} selected")
                    return list_readers[i].createConnection()
            logging.error("Can't find the initial reader")
        else:
            pass
        logging.info(f"Default (first) reader selected: {str(list_readers[0])}")
        return list_readers[0].createConnection()
    logging.error("No reader identified")
    return None