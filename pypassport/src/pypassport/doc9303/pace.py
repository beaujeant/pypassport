"""
From https://github.com/tsenger/pypace
https://github.com/AndyQ/NFCPassportReader/blob/main/Sources/NFCPassportReader/PACEHandler.swift
https://github.com/jllarraz/AndroidPassportReader/blob/master/app/src/main/java/example/jllarraz/com/passportreader/utils/PassportNFC.kt
"""
from hashlib import sha1
from smartcard.util import toHexString
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Hash import CMAC, SHA
from binascii import hexlify
from ecdsa.ellipticcurve import Point, CurveFp
from ecdsa.curves import Curve
#from pytlv.TLV import *
import binascii
import logging

from pypassport.iso7816 import ISO7816Exception
from pypassport.utils import long_to_bytearray, hex_to_int
from pypassport.doc9303.mrz import MRZ

from pyasn1.codec.der.decoder import decode as asn1decode

DEBUG_CRYPTO = False

# https://github.com/henryk/cyberflex-shell/blob/master/oids.txt

pace_oid = {
    "0.4.0.127.0.7.2.2.4.2.2": "id-PACE-ECDH-GM-AES-CBC-CMAC-128"
}

ef_security_object = ["DG14, CardAccess"]

class PACEException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class PACE:
    
    def __init__(self, iso7816, mrz=None, password=None):
        self.__load_brainpool()
        self._iso7816 = iso7816
        self._password = password
        self._password = None
        if mrz:
            self._password = self.genKseed(mrz)

    def genKseed(self, mrz):
        """
        Take an MRZ object and construct the MRZ information out of the MRZ extracted informations:
            - The Document number + Check digit
            - The Date of Birth + CD
            - The Data of Expirity + CD
        Then hash (SHA-1) for the kseed

        @param mrz: An MRZ object
        @type mrz: MRZ object
        @return: the mrz information used for the key derivation
        """

        if isinstance(mrz, str):
            MRZ(mrz)
        elif not isinstance(mrz, MRZ):
            raise PACException("Bad parameter, must be an MRZ object (" + str(type(mrz)) + ")")

        kmrz = mrz.docNumber[0] + mrz.docNumber[1] + \
            mrz.dateOfBirth[0] + mrz.dateOfBirth[1] + \
            mrz.dateOfExpiry[0] + mrz.dateOfExpiry[1]

        logging.debug("Construct the 'MRZ_information' out of the MRZ")
        logging.debug("\tDocument number: " + mrz.docNumber[0] + "\tCheck digit: " + mrz.docNumber[1])
        logging.debug("\tDate of birth: " + mrz.dateOfBirth[0] + "\t\tCheck digit: " + mrz.dateOfBirth[1])
        logging.debug("\tDate of expiry: " + mrz.dateOfExpiry[0] + "\t\tCheck digit: " + mrz.dateOfExpiry[1])
        logging.debug("\tMRZ_information: " + kmrz)

        if DEBUG_CRYPTO: logging.debug("Calculate the SHA-1 hash of MRZ_information")

        kseedhash = sha1(kmrz.encode())
        kseed = kseedhash.digest()

        if DEBUG_CRYPTO: logging.debug("\tHsha1(MRZ_information): " + toHexString(kseed))

        return kseed


    def getSecurityObject(self):
        for ef in ef_security_object:
            try:
                self._iso7816selectElementaryFile
            except ISO7816Exception as e:
                if e.sw1 == 0x90 and e.sw2 == 0x00:
                    pass


    def getPACEInfo(self, security_object):
        obj = []
        data = security_object
        oid = None
        domain = None

        elements, _ = asn1decode(data)

        for seq in elements:
            try:
                if str(seq[0]) in pace_oid:
                    logging.debug(f"PACE OID: {seq[0]}")
                    logging.debug(f"PACE Domain: {seq[2]}")
                    oid = bytes(seq[0])
                    domain = bytes([seq[2]])
                    break
            except Exception:
                continue
        return oid, domain


    def __getX1(self):
        self.__PCD_SK_x1 = hex_to_int(bytearray(get_random_bytes(32)))
        PCD_PK_X1 = self.pointG * self.__PCD_SK_x1
        return bytearray(bytearray([0x04])+long_to_bytearray(PCD_PK_X1.x())+ long_to_bytearray(PCD_PK_X1.y()))
    
    
    def __getX2(self, PICC_PK, decryptedNonce):
        x = PICC_PK[1:33]
        y = PICC_PK[33:]
        
        pointY1 = Point( self.curve_brainpoolp256r1, hex_to_int(x), hex_to_int(y), self._q)
        sharedSecret_P = pointY1 * self.__PCD_SK_x1
        pointG_strich = (self.pointG * hex_to_int(decryptedNonce)) + sharedSecret_P
        
        self.__PCD_SK_x2 = hex_to_int(bytearray(get_random_bytes(32)))
        PCD_PK_X2 = pointG_strich * self.__PCD_SK_x2
        return bytearray(bytearray([0x04])+long_to_bytearray(PCD_PK_X2.x())+ long_to_bytearray(PCD_PK_X2.y()))


    def __sendGA2(self, PCD_PK):
        header = bytearray([0x10, 0x86, 0, 0, len(PCD_PK)+4, 0x7c, len(PCD_PK)+2, 0x81, len(PCD_PK)])
        response = self.__transceiveAPDU(list(header + PCD_PK)+[0])
        return response[4:]
    
    
    def __sendGA3(self, PCD_PK):
        header = bytearray([0x10, 0x86, 0, 0, len(PCD_PK)+4, 0x7c, len(PCD_PK)+2, 0x83, len(PCD_PK)])
        response = self.__transceiveAPDU(list(header + PCD_PK)+[0])
        return bytearray(response[4:])
    
    
    def __sendGA4(self, authToken):
        header = bytearray([0x00, 0x86, 0, 0, len(authToken)+4, 0x7c, len(authToken)+2, 0x85, len(authToken)])
        response = self.__transceiveAPDU(list(header + authToken)+[0])
        
        tlv = TLV(['86', '87', '88']) # DO87 and DO88 are optional
        
        collection = tlv.parse(binascii.hexlify(response[2:])) 
        
        if (collection.get('86') != None):
            DO86 = bytearray.fromhex(collection.get('86'))
        else:
            DO86 = None
        
        if (collection.get('87') != None):
            DO87 = bytearray.fromhex(collection.get('87'))
        else:
            DO87 = None

        if (collection.get('88') != None):
            DO88 = bytearray.fromhex(collection.get('88'))
        else:
            DO88 = None

        return DO86, DO87, DO88

    
    def __getSharedSecret(self, PICC_PK):
        x = PICC_PK[1:33]
        y = PICC_PK[33:]
        pointY2 = Point( self.curve_brainpoolp256r1, hex_to_int(x), hex_to_int(y), self._q)
        K = pointY2 * self.__PCD_SK_x2
        return long_to_bytearray(K.x())
    
    
    def __calcAuthToken(self, kmac, algorithm_oid, Y2):
        oid_input = [0x06, len(algorithm_oid)] +algorithm_oid
        mac_input = [0x7f, 0x49, len(oid_input)+len(Y2)+2] + oid_input + [0x86, len(Y2)] + list(Y2)
        logging.debug("Mac input: " + toHexString(mac_input))
        return bytearray(self.getCMAC(kmac, bytearray(mac_input)))[:8]
    
    
    def __load_brainpool(self):
        # Brainpool P-256-r1
        _a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
        _b = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
        _p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
        _Gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
        _Gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
        self._q = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
        
        self.curve_brainpoolp256r1 = CurveFp( _p, _a, _b)
        self.pointG = Point(self.curve_brainpoolp256r1, _Gx, _Gy, self._q)
    
    def performPACE(self, algorithm_oid, pw_ref, domain_params=b"", chat=b""):
        logging.debug("Starting PACE")
        # Don't know why the first 00 is not taken
        #algorithm_oid = algorithm_oid[1:]
        self._iso7816.mseSetAt(algorithm_oid, pw_ref, domain_params, chat)
        
        encryptedNonce = self._iso7818.generalAuthenticate()[4:20]
        logging.info("PACE encrypted nonce: " + toHexString(list(encryptedNonce)))
        """
        #decryptedNonce = self.__decryptNonce(encryptedNonce, password)
        decryptedNonce = self.decryptBlock(self.kdf(password, 3), encryptedNonce)
        logging.info("PACE decrypted nonce: " + toHexString(list(decryptedNonce)))
    
        PCD_PK_X1 = self.__getX1()
        logging.info("PACE PCD_PK_X1: "+toHexString(list(PCD_PK_X1)))
        PICC_PK_Y1 = self.__sendGA2(PCD_PK_X1)
        logging.info("PACE PICC_PK_Y1: "+toHexString(list(PICC_PK_Y1)))
        
        PCD_PK_X2 = self.__getX2(PICC_PK_Y1, decryptedNonce)
        logging.info("PACE PCD_PK_X2: "+toHexString(list(PCD_PK_X2)))
        PICC_PK_Y2 = self.__sendGA3(PCD_PK_X2)
        logging.info("PACE PICC_PK_Y2: "+toHexString(list(PICC_PK_Y2)))
        
        sharedSecretK = self.__getSharedSecret(PICC_PK_Y2)
        logging.info("PACE Shared Secret K: "+toHexString(list(sharedSecretK)))
        
        kenc = self.kdf(sharedSecretK, 1)
        logging.info("PACE K_enc: "+toHexString(list(kenc)))
        
        kmac = self.kdf(sharedSecretK, 2)
        logging.info("PACE K_mac: "+toHexString(list(kmac)))
        
        tpcd = self.__calcAuthToken(kmac, algorithm_oid, PICC_PK_Y2)
        logging.info("PACE tpcd: "+toHexString(list(tpcd)))
    
        tpicc, car1, car2 = self.__sendGA4(tpcd)
        logging.info("PACE tpicc: "+toHexString(list(tpicc)))
        if (car1 != None):
            logging.info("CAR1: "+ car1)
        if (car2 != None):
            logging.info("CAR2: "+ car2)
        
        tpicc_strich = self.__calcAuthToken(kmac, algorithm_oid, PCD_PK_X2);
        
        if tpicc == tpicc_strich:
            logging.info("PACE established!")
            return 0
        else:
             logging.info("PACE failed!");
             return -1
        """

    def decryptBlock(self, key, ciphertext):
        aes = AES.new(str(key), AES.MODE_ECB)
        return bytearray(aes.decrypt(str(ciphertext)))
        
    def encryptBlock(self, key, plaintext):
        aes = AES.new(str(key), AES.MODE_ECB)
        return bytearray(aes.encrypt(str(plaintext)))

    def decrypt(self, key, ssc, ciphertext):
        iv = self.encryptBlock(key, ssc)
        aes = AES.new(str(key), AES.MODE_CBC, str(iv))
        paddedCiphertext = self.aes.decrypt(ciphertext)
        return bytearray(self.addPadding(str(paddedCiphertext)))

    def encrypt(self, key, ssc, plaintext):
        iv = self.encryptBlock(key, ssc)
        aes = AES.new(str(key), AES.MODE_CBC, str(iv))
        paddedPlaintext = self.addPadding(str(plaintext))
        return bytearray(aes.encrypt(paddedPlaintext))

    def getMAC(self, key, ssc, data):
        n = ssc + data
        paddedn = self.addPadding(n)
        cmac = CMAC.new(str(key), ciphermod=AES)
        cmac.update(paddedn)
        return bytearray(cmac.digest())
    
    def getCMAC(self, key, data):
        cmac = CMAC.new(str(key), ciphermod=AES)
        cmac.update(str(data))
        return bytearray(cmac.digest())

    def kdf(self, password, c):
        intarray = [0, 0, 0 , c]
        mergedData = list(bytearray(password)) + intarray
        sha = SHA.new()
        sha.update(bytearray(mergedData))
        return bytearray(sha.digest())[0:16]
    
    def addPadding(self, data):
        return Padding.pad(str(data), AES.block_size, style='iso7816')