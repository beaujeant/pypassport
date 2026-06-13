# Copyright 2012 Antonin Beaujeant
#
# This file is part of pypassport.
#
# pypassport is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# pypassport is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with pyPassport.
# If not, see <http://www.gnu.org/licenses/>.

import datetime
import json
import logging
import os

from pypassport.iso7816 import ISO7816, APDUCommand

class ErrorFingerprintingException(Exception):
    pass

class ErrorFingerprinting():
    """
    ICAO described minimum required instruction for the communication between the reader and the passport.
    Therefore, regarding features implemented, a passport might behave in a different way with a different error message
    This lack of standardisation creates a fingerprint an attacker could use to identify the issuer and the version of the passport.
    This class implements methods in order to store error regarding the country and the version and identify a passport.

    The error database is persisted as JSON (human-readable and diff-able)
    rather than pickle.
    """

    def __init__(self, iso7816, path="error.json"):
        logging.info("ERROR FINGERPRINTING")
        self._iso7816 = iso7816

        if not isinstance(self._iso7816, ISO7816):
            raise ErrorFingerprintingException("The sublayer iso7816 is not available")

        self._iso7816.rstConnection()

        self._path = path

        if os.path.exists(path):
            with open(path, 'r') as file_errors:
                self.errors = json.load(file_errors)
        else:
            self.errors = { "0000000000": { "0x6d 0x0": {   "BEL": ["2009", "2011"],
                                                            "FRA": ["2010"]
                                                        }
                                          }
                          }

    def sendCustom(self, cla="00", ins="00", p1="00", p2="00", lc="", data="", le="00"):
        """
        Send custom APDU in order to trigger errors.

        @param cla, ins, p1, p2, lc, data, le: APDU value
        @type cla, ins, p1, p2, lc, data, le: String of 2hex (from 00 to FF) except lc and date that may be an empty String

        @return: A tuple (success, APDUResponse) where success is True when the
            chip returned a success status word and False otherwise.
        """

        toSend = APDUCommand(cla, ins, p1, p2, lc, data, le)

        logging.info("Send APDU: {0}:{1}:{2}:{3}:{4}:{5}:{6}".format(cla, ins, p1, p2, lc, data, le))
        response = self._iso7816.transmit(toSend, "Custom APDU", full=True)
        success = response.status == "Success"
        return (success, response)

    def addError(self, new_query, ans, new_country, year=str(datetime.datetime.today().year)):
        """
        Add in the error dictionary (self.errors + save in file) a set composed of:
         - The APDU sent
         - The error received
         - Issuer (country)
         - The version (year)

        @param new_query: The APDU sent
        @type new_query: String of 10 to 14 hex
        @param ans: The answer from the passport
        @type ans: A tuple (success, APDUResponse) as returned by sendCustom()
        @param new_country: The issuer (country)
        @type new_country: String of 3 char (Official country id)
        @param year: The passport version (date of issue)
        @type year: String of 4 digits (i.e. "2012")
        """

        (success, response) = ans
        if success:
            raise ErrorFingerprintingException("The query triggered no error")
        new_error = "{0} {1}".format(hex(response.sw1), hex(response.sw2))
        i=True
        for query in self.errors:
            if query==new_query:
                for error in self.errors[query]:
                    if error==new_error:
                        for country in self.errors[query][error]:
                            if country==new_country:
                                for date in self.errors[query][error][country]:
                                    if date==year:
                                        logging.info("The entry already exists")
                                        i=False
                                if i:
                                    self.errors[new_query][new_error][new_country].append(year)
                                    logging.info("The entry has been added")
                                    i=False
                        if i:
                            self.errors[new_query][new_error][new_country] = [year]
                            logging.info("The entry has been added")
                            i=False
                if i:
                    self.errors[new_query][new_error] = { new_country: [year] }
                    logging.info("The entry has been added")
                    i=False
        if i:
            self.errors[new_query] = { new_error: { new_country: [year] } }
            logging.info("The entry has been added")
            i=False

        with open(self._path, 'w') as file_errors:
            logging.info("Save the dictionary")
            json.dump(self.errors, file_errors, indent=2, sort_keys=True)

    def identify(self, cla="00", ins="00", p1="00", p2="00", lc="", data="", le="00"):
        """
        Identify a passport by sending a custom APDU and checking the answer in the error dictionary

        @param cla, ins, p1, p2, lc, data, le: APDU value
        @type cla, ins, p1, p2, lc, data, le: String of 2hex (from 00 to FF) except lc and date that may be an empty String

        @raise ErrorFingerprintingException: If the query triggered no error, it raises an error

        @return: Return all the possible issuer-version the passport might belong to.
        """

        cur_query = cla + ins + p1 + p2 + lc + data + le
        (success, response) = self.sendCustom(cla, ins, p1, p2, lc, data, le)
        if success:
            raise ErrorFingerprintingException("Not possible to identify the passport since the query is correct")
        new_error = "{0} {1}".format(hex(response.sw1), hex(response.sw2))
        possibilities = list()

        logging.info("Check for error: {0}".format(new_error))
        for query in self.errors:
            if query==cur_query:
                for error in self.errors[query]:
                    if error==new_error:
                        for country in self.errors[query][error]:
                            cur_country = country
                            for date in self.errors[query][error][country]:
                                possibilities.append("{0} {1}".format(cur_country, date))

        return possibilities











