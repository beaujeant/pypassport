"""
Access-control negotiation for ICAO 9303 ePassports.

Modern passports may require PACE; legacy passports support BAC only. This
module reads EF.CardAccess (when allowed by the configured mode), decides
between PACE and BAC, runs the chosen mechanism, and selects the eMRTD
application so the caller can read LDS files under secure messaging.

Public entry point: ``AccessControlNegotiator.open(mrz)``.
"""

import logging
from typing import Optional

from pypassport.doc9303 import secure_messaging
from pypassport.doc9303.bac import BAC, BACException
from pypassport.doc9303.card_access import (
    CardAccessNotFound,
    CardAccessReadError,
    CardAccessReader,
)
from pypassport.doc9303.mrz import MRZ
from pypassport.doc9303.pace import PACE, PACEException
from pypassport.doc9303.security_info import (
    PACEInfo,
    SecurityInfoParser,
    SecurityInfoParseError,
)
from pypassport.iso7816 import ISO7816Exception


# AID of the ICAO eMRTD application.
EMRTD_AID = "A0000002471001"

MODE_AUTO = "auto"
MODE_PACE = "pace"
MODE_BAC = "bac"
MODE_NONE = "none"
_SUPPORTED_MODES = (MODE_AUTO, MODE_PACE, MODE_BAC, MODE_NONE)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AccessControlNegotiationError(Exception):
    """Base class for access-control negotiation failures."""

    def __init__(self, message, mechanism=None, sw1=None, sw2=None):
        super().__init__(message)
        self.mechanism = mechanism
        self.sw1 = sw1
        self.sw2 = sw2


class NoSupportedPACEInfo(AccessControlNegotiationError):
    """EF.CardAccess was read but contained no PACEInfo we can handle."""


class PACEAuthenticationError(AccessControlNegotiationError):
    """PACE was attempted but did not produce a working secure channel."""


class BACAuthenticationError(AccessControlNegotiationError):
    """BAC was attempted but failed. The message includes a 6A88 hint."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class NegotiationResult:
    """Outcome of a successful access-control negotiation."""

    def __init__(self, mechanism: str, pace_info: Optional[PACEInfo] = None):
        self.mechanism = mechanism  # "PACE" or "BAC"
        self.pace_info = pace_info

    def __repr__(self):
        if self.pace_info is not None:
            return f"<NegotiationResult mechanism={self.mechanism} oid={self.pace_info.oid}>"
        return f"<NegotiationResult mechanism={self.mechanism}>"


# ---------------------------------------------------------------------------
# Thin authenticator wrappers
# ---------------------------------------------------------------------------


class BACAuthenticator:
    """Run BAC and install Secure Messaging on the iso7816 layer."""

    def __init__(self, iso7816):
        self._iso7816 = iso7816
        self._bac = BAC(iso7816)

    def authenticate(self, mrz: MRZ) -> None:
        logging.info("Access control: running BAC")
        try:
            ksenc, ksmac, ssc = self._bac.authenticationAndEstablishmentOfSessionKeys(mrz)
        except BACException as exc:
            raise BACAuthenticationError(
                _bac_diagnostic(exc),
                mechanism="BAC",
            ) from exc
        except ISO7816Exception as exc:
            raise BACAuthenticationError(
                _bac_diagnostic(exc),
                mechanism="BAC",
                sw1=exc.sw1, sw2=exc.sw2,
            ) from exc

        sm = secure_messaging.SecureMessaging(ksenc, ksmac, ssc)
        self._iso7816.ciphering = sm


class PACEAuthenticator:
    """
    Run PACE with the configured secret (MRZ-derived or CAN) and install
    Secure Messaging on the iso7816 layer.

    If ``can`` is provided, PACE is run with the Card Access Number
    (password reference 0x02). Otherwise it falls back to the MRZ
    (password reference 0x01).
    """

    def __init__(self, iso7816, mrz: Optional[MRZ] = None, can: Optional[str] = None):
        if can is None and mrz is None:
            raise AccessControlNegotiationError(
                "PACE requires either an MRZ or a CAN."
            )
        self._iso7816 = iso7816
        self._pace = PACE(iso7816, mrz=mrz, can=can)
        self._secret_label = "CAN" if can is not None else "MRZ"

    def authenticate(self, info: PACEInfo) -> None:
        logging.info(
            "Access control: running PACE (%s/%s/%s-%d) with %s",
            info.key_agreement or "?", info.mapping or "?",
            info.cipher or "?", info.key_size or 0,
            self._secret_label,
        )

        # Build the algorithm OID and (optionally) the domain parameter id.
        oid_bytes = _oid_to_der_value(info.oid)
        domain = bytes([info.parameter_id]) if info.parameter_id is not None else b""

        pw_ref = self._pace.password_reference or PACE.PWD_MRZ
        try:
            self._pace.performPACE(oid_bytes, pw_ref, domain_params=domain)
        except NotImplementedError as exc:
            raise PACEAuthenticationError(
                "PACE selected but the local implementation is incomplete: "
                f"{exc}. Use access_control='bac' to force BAC, or upgrade pypassport.",
                mechanism="PACE",
            ) from exc
        except PACEException as exc:
            raise PACEAuthenticationError(
                f"PACE failed: {exc}",
                mechanism="PACE",
            ) from exc
        except ISO7816Exception as exc:
            raise PACEAuthenticationError(
                f"PACE failed: chip returned "
                f"{(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X} ({exc.data}).",
                mechanism="PACE",
                sw1=exc.sw1, sw2=exc.sw2,
            ) from exc

        # If we reach this point but no SecureMessaging context has been
        # installed by the PACE implementation, the protocol did not
        # complete — fail loudly rather than silently continuing without
        # an encrypted channel.
        if not self._iso7816.ciphering:
            raise PACEAuthenticationError(
                "PACE did not establish a Secure Messaging channel. "
                "The PACE backend in this version of pypassport is partial; "
                "use access_control='bac' to force BAC instead.",
                mechanism="PACE",
            )


# ---------------------------------------------------------------------------
# Negotiator
# ---------------------------------------------------------------------------


class AccessControlNegotiator:
    """
    Decide between PACE and BAC, run the chosen mechanism, then select the
    eMRTD application.
    """

    def __init__(self, iso7816):
        self._iso7816 = iso7816
        self._card_access_reader = CardAccessReader(iso7816)
        self._parser = SecurityInfoParser()

    def open(self, mrz, mode: str = MODE_AUTO, can: Optional[str] = None) -> NegotiationResult:
        """
        Run the configured access-control flow and select the eMRTD AID.

        :param mrz: An MRZ object. Required for BAC (and for PACE if no CAN
            is given). Ignored for ``none``.
        :param mode: One of ``"auto"``, ``"pace"``, ``"bac"``, ``"none"``.
        :param can: Optional Card Access Number. When provided, PACE will be
            attempted using the CAN as the password instead of the MRZ.
        :return: A NegotiationResult describing what ran.
        :raise AccessControlNegotiationError: On unknown mode, missing
            credentials, or any failure that cannot be recovered.
        """
        mode = (mode or MODE_AUTO).lower()
        if mode not in _SUPPORTED_MODES:
            raise AccessControlNegotiationError(
                f"Unknown access_control mode '{mode}'. "
                f"Supported: {', '.join(_SUPPORTED_MODES)}."
            )

        if mode == MODE_BAC and mrz is None:
            raise AccessControlNegotiationError(
                "MRZ is required for access_control='bac'."
            )
        if mode == MODE_PACE and mrz is None and can is None:
            raise AccessControlNegotiationError(
                "PACE requires either an MRZ or a CAN."
            )
        if mode == MODE_AUTO and mrz is None and can is None:
            raise AccessControlNegotiationError(
                "access_control='auto' requires an MRZ (and optionally a CAN)."
            )

        if mode == MODE_NONE:
            logging.warning("Access control mode 'none' — no secure messaging will be set up.")
            self._select_emrtd_application()
            return NegotiationResult(mechanism="NONE")

        if mode == MODE_BAC:
            BACAuthenticator(self._iso7816).authenticate(mrz)
            self._select_emrtd_application()
            return NegotiationResult(mechanism="BAC")

        # auto or pace — read EF.CardAccess first.
        pace_info = self._discover_pace_info(mandatory=(mode == MODE_PACE))

        if pace_info is not None:
            try:
                PACEAuthenticator(self._iso7816, mrz=mrz, can=can).authenticate(pace_info)
                self._select_emrtd_application()
                return NegotiationResult(mechanism="PACE", pace_info=pace_info)
            except PACEAuthenticationError:
                if mode == MODE_PACE or mrz is None:
                    raise
                logging.warning("PACE failed; falling back to BAC.")

        # auto mode — fall back to BAC.
        BACAuthenticator(self._iso7816).authenticate(mrz)
        self._select_emrtd_application()
        return NegotiationResult(mechanism="BAC")

    def _discover_pace_info(self, *, mandatory: bool) -> Optional[PACEInfo]:
        """
        Read and parse EF.CardAccess, return a supported PACEInfo or None.

        :param mandatory: If True, raise on any failure (mode='pace'). If
            False, swallow recoverable errors and return None (mode='auto').
        """
        try:
            raw = self._card_access_reader.read()
        except CardAccessNotFound as exc:
            if mandatory:
                raise AccessControlNegotiationError(
                    "EF.CardAccess is not available on this chip, but PACE was required: "
                    f"{exc}", mechanism="PACE", sw1=exc.sw1, sw2=exc.sw2,
                ) from exc
            logging.info("EF.CardAccess not found; assuming BAC-only chip.")
            return None
        except CardAccessReadError as exc:
            if mandatory:
                raise AccessControlNegotiationError(
                    f"Could not read EF.CardAccess: {exc}",
                    mechanism="PACE", sw1=exc.sw1, sw2=exc.sw2,
                ) from exc
            logging.warning("EF.CardAccess read error: %s; falling back to BAC.", exc)
            return None

        try:
            infos = self._parser.parse(raw)
        except SecurityInfoParseError as exc:
            if mandatory:
                raise AccessControlNegotiationError(
                    f"EF.CardAccess could not be parsed: {exc}",
                    mechanism="PACE",
                ) from exc
            logging.warning("EF.CardAccess parse error: %s; falling back to BAC.", exc)
            return None

        if not infos:
            if mandatory:
                raise NoSupportedPACEInfo(
                    "EF.CardAccess contained no PACEInfo entries.",
                    mechanism="PACE",
                )
            logging.info("No PACEInfo entries in EF.CardAccess; falling back to BAC.")
            return None

        chosen = self._parser.select_supported(infos)
        if chosen is None:
            unsupported = ", ".join(info.oid for info in infos)
            if mandatory:
                raise NoSupportedPACEInfo(
                    "No supported PACEInfo found in EF.CardAccess. "
                    f"Chip advertised: {unsupported}.",
                    mechanism="PACE",
                )
            logging.info(
                "No PACEInfo OID in EF.CardAccess is supported (advertised: %s); "
                "falling back to BAC.", unsupported,
            )
            return None

        return chosen

    def _select_emrtd_application(self):
        try:
            self._iso7816.selectDedicatedFile(EMRTD_AID)
        except ISO7816Exception as exc:
            raise AccessControlNegotiationError(
                f"Could not select the eMRTD application (AID {EMRTD_AID}): "
                f"SW={(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X} ({exc.data}).",
                sw1=exc.sw1, sw2=exc.sw2,
            ) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bac_diagnostic(exc) -> str:
    """Produce a helpful error message for a failed BAC, including the 6A88 hint."""
    sw1 = getattr(exc, "sw1", None)
    sw2 = getattr(exc, "sw2", None)
    base = str(exc)
    if sw1 == 0x6A and sw2 == 0x88:
        return (
            f"{base} BAC-related referenced data was not found (6A88). "
            "This document may require PACE — try access_control='auto' "
            "or access_control='pace'."
        )
    return base


def _oid_to_der_value(oid: str) -> bytes:
    """
    Encode a dotted-string OID as the *value* of an ASN.1 OBJECT IDENTIFIER
    (no tag, no length). This matches what ``iso7816.mseSetAt`` expects.
    """
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid!r}")
    first = 40 * parts[0] + parts[1]
    out = bytearray([first])
    for value in parts[2:]:
        if value < 0:
            raise ValueError(f"Invalid OID component in {oid!r}")
        if value == 0:
            out.append(0)
            continue
        sub = []
        while value:
            sub.append(value & 0x7F)
            value >>= 7
        sub.reverse()
        for i in range(len(sub) - 1):
            sub[i] |= 0x80
        out.extend(sub)
    return bytes(out)
