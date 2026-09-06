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

    def __init__(
        self,
        mechanism: str,
        pace_info: Optional[PACEInfo] = None,
        *,
        advertised_pace_infos: Optional[list[PACEInfo]] = None,
        attempts: Optional[list[dict]] = None,
        fallback_reason: Optional[str] = None,
        cam_result=None,
        card_security=None,
    ):
        self.mechanism = mechanism  # "PACE" or "BAC"
        self.pace_info = pace_info
        self.advertised_pace_infos = list(advertised_pace_infos or [])
        self.attempts = list(attempts or [])
        self.fallback_reason = fallback_reason
        self.downgraded = mechanism == "BAC" and bool(self.advertised_pace_infos or fallback_reason)
        self.cam_result = cam_result
        self.card_security = card_security

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
            ksenc, ksmac, ssc = self._bac.authentication_and_establishment_of_session_keys(mrz)
        except BACException as exc:
            raise BACAuthenticationError(
                _bac_diagnostic(exc),
                mechanism="BAC",
            ) from exc
        except ISO7816Exception as exc:
            raise BACAuthenticationError(
                _bac_diagnostic(exc),
                mechanism="BAC",
                sw1=exc.sw1,
                sw2=exc.sw2,
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

    def __init__(self, iso7816, mrz: Optional[MRZ] = None, can=None, pin=None, puk=None, password=None):
        if all(x is None for x in (can, pin, puk, password, mrz)):
            raise AccessControlNegotiationError("PACE requires an MRZ, CAN, PIN, PUK, or raw password.")
        self._iso7816 = iso7816
        self._pace = PACE(iso7816, mrz=mrz, can=can, pin=pin, puk=puk, password=password)
        self._secret_label = next((name for name, value in (("CAN", can), ("PIN", pin), ("PUK", puk), ("raw", password)) if value is not None), "MRZ")

    def authenticate(self, info: PACEInfo, *, include_parameter_reference=False) -> None:
        logging.info(
            "Access control: running PACE (%s/%s/%s-%d) with %s",
            info.key_agreement or "?",
            info.mapping or "?",
            info.cipher or "?",
            info.key_size or 0,
            self._secret_label,
        )

        # Build the algorithm OID and (optionally) the domain parameter id.
        oid_bytes = _oid_to_der_value(info.oid)
        width = max(1, (info.parameter_id.bit_length() + 7) // 8) if info.parameter_id is not None else 0
        domain = info.parameter_id.to_bytes(width, "big") if include_parameter_reference and info.parameter_id is not None else b""

        pw_ref = self._pace.password_reference or PACE.PWD_MRZ
        try:
            self._pace.perform_pace(oid_bytes, pw_ref, domain_params=domain,
                                    explicit_domain_parameters=info.domain_parameters, parameter_id=info.parameter_id)
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
                f"PACE failed: chip returned {(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X} ({exc.data}).",
                mechanism="PACE",
                sw1=exc.sw1,
                sw2=exc.sw2,
            ) from exc

        # If we reach this point but no SecureMessaging context has been
        # installed by the PACE implementation, the protocol did not
        # complete — fail loudly rather than silently continuing without
        # an encrypted channel.
        if self._iso7816.ciphering is None:
            raise PACEAuthenticationError(
                "PACE did not establish a Secure Messaging channel. "
                "The PACE backend in this version of pypassport is partial; "
                "use access_control='bac' to force BAC instead.",
                mechanism="PACE",
            )
        if info.mapping == "CAM":
            from pypassport.doc9303.data_group import read_elementary_file

            self.card_security = read_elementary_file("CardSecurity", self._iso7816)
            self.cam_result = self._pace.verify_cam(self.card_security)


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
        self._parser: SecurityInfoParser = SecurityInfoParser()

    def open(
        self,
        mrz,
        mode: str = MODE_AUTO,
        can: Optional[str] = None,
        *,
        pin=None,
        puk=None,
        password=None,
        allow_bac_fallback: bool = False,
    ) -> NegotiationResult:
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
                f"Unknown access_control mode '{mode}'. Supported: {', '.join(_SUPPORTED_MODES)}."
            )

        if mode == MODE_BAC and mrz is None:
            raise AccessControlNegotiationError("MRZ is required for access_control='bac'.")
        if mode == MODE_PACE and all(x is None for x in (mrz, can, pin, puk, password)):
            raise AccessControlNegotiationError("PACE requires an MRZ, CAN, PIN, PUK, or raw password.")
        if mode == MODE_AUTO and all(x is None for x in (mrz, can, pin, puk, password)):
            raise AccessControlNegotiationError("access_control='auto' requires a PACE password or BAC MRZ.")

        if mode == MODE_NONE:
            logging.warning("Access control mode 'none' — no secure messaging will be set up.")
            self._select_emrtd_application()
            return NegotiationResult(mechanism="NONE")

        if mode == MODE_BAC:
            self._select_emrtd_application()
            BACAuthenticator(self._iso7816).authenticate(mrz)
            return NegotiationResult(mechanism="BAC", attempts=[{"mechanism": "BAC", "result": "success"}])

        # auto or pace — read EF.CardAccess first.
        pace_info = self._discover_pace_info(mandatory=(mode == MODE_PACE))
        pace_candidates = list(getattr(self, "_pace_candidates", [pace_info] if pace_info else []))
        advertised = list(getattr(self, "_advertised_pace_infos", []))
        attempts: list[dict] = []
        fallback_reason = getattr(self, "_pace_discovery_problem", None)

        safe_legacy_fallback = fallback_reason in ("cardaccess_missing", "cardaccess_contains_no_pace_info")
        if mode == MODE_AUTO and fallback_reason and not safe_legacy_fallback and not allow_bac_fallback:
            raise AccessControlNegotiationError(
                f"PACE discovery failed and BAC fallback is disabled: {fallback_reason}", mechanism="PACE"
            )

        for candidate_no, pace_info in enumerate(pace_candidates):
            try:
                authenticator_args = {"mrz": mrz, "can": can}
                authenticator_args.update({name: value for name, value in (("pin", pin), ("puk", puk), ("password", password)) if value is not None})
                authenticator = PACEAuthenticator(self._iso7816, **authenticator_args)
                if sum(x.oid == pace_info.oid for x in advertised) > 1:
                    authenticator.authenticate(pace_info, include_parameter_reference=True)
                else:
                    authenticator.authenticate(pace_info)
                self._select_emrtd_application()
                attempts.append({"mechanism": "PACE", "oid": pace_info.oid, "result": "success"})
                return NegotiationResult(
                    mechanism="PACE", pace_info=pace_info, advertised_pace_infos=advertised, attempts=attempts,
                    cam_result=getattr(authenticator, "cam_result", None),
                    card_security=getattr(authenticator, "card_security", None),
                )
            except PACEAuthenticationError as exc:
                attempts.append({"mechanism": "PACE", "oid": pace_info.oid, "result": "failed", "error": str(exc)})
                fallback_reason = f"PACE authentication failed: {exc}"
                if candidate_no + 1 < len(pace_candidates):
                    try:
                        self._iso7816.rst_connection_raw()
                        self._card_access_reader.read()
                    except Exception as reset_exc:
                        raise PACEAuthenticationError(f"Could not reset for the next PACEInfo: {reset_exc}") from reset_exc
                    continue
                if mode == MODE_PACE or mrz is None or not allow_bac_fallback:
                    raise
                logging.warning("PACE failed; falling back to BAC.")
                # A failed PACE leaves the chip in a sticky auth-pending
                # state where BAC returns 6A88. Reset the card so BAC can
                # start from a clean slate.
                try:
                    self._iso7816.rst_connection_raw()
                except Exception as exc:
                    logging.warning("Could not reset card before BAC fallback: %s", exc)

        # auto mode — fall back to BAC.
        self._select_emrtd_application()
        BACAuthenticator(self._iso7816).authenticate(mrz)
        attempts.append({"mechanism": "BAC", "result": "success"})
        return NegotiationResult(
            mechanism="BAC",
            advertised_pace_infos=advertised,
            attempts=attempts,
            fallback_reason=fallback_reason,
        )

    def _discover_pace_info(self, *, mandatory: bool) -> Optional[PACEInfo]:
        """
        Read and parse EF.CardAccess, return a supported PACEInfo or None.

        :param mandatory: If True, raise on any failure (mode='pace'). If
            False, swallow recoverable errors and return None (mode='auto').
        """
        try:
            raw = self._card_access_reader.read()
        except CardAccessNotFound as exc:
            self._advertised_pace_infos = []
            self._pace_discovery_problem = "cardaccess_missing"
            if mandatory:
                raise AccessControlNegotiationError(
                    f"EF.CardAccess is not available on this chip, but PACE was required: {exc}",
                    mechanism="PACE",
                    sw1=exc.sw1,
                    sw2=exc.sw2,
                ) from exc
            logging.info("EF.CardAccess not found; assuming BAC-only chip.")
            return None
        except CardAccessReadError as exc:
            self._advertised_pace_infos = []
            self._pace_discovery_problem = f"cardaccess_read_error: {exc}"
            if mandatory:
                raise AccessControlNegotiationError(
                    f"Could not read EF.CardAccess: {exc}",
                    mechanism="PACE",
                    sw1=exc.sw1,
                    sw2=exc.sw2,
                ) from exc
            logging.warning("EF.CardAccess read error: %s; falling back to BAC.", exc)
            return None

        try:
            infos = self._parser.parse(raw)
        except SecurityInfoParseError as exc:
            self._advertised_pace_infos = []
            self._pace_discovery_problem = f"cardaccess_parse_error: {exc}"
            if mandatory:
                raise AccessControlNegotiationError(
                    f"EF.CardAccess could not be parsed: {exc}",
                    mechanism="PACE",
                ) from exc
            logging.warning("EF.CardAccess parse error: %s; falling back to BAC.", exc)
            return None

        self._advertised_pace_infos = list(infos)
        self._pace_discovery_problem = None
        if not infos:
            self._pace_discovery_problem = "cardaccess_contains_no_pace_info"
            if mandatory:
                raise NoSupportedPACEInfo(
                    "EF.CardAccess contained no PACEInfo entries.",
                    mechanism="PACE",
                )
            logging.info("No PACEInfo entries in EF.CardAccess; falling back to BAC.")
            return None

        self._pace_candidates = self._parser.select_all_supported(infos)
        chosen = self._pace_candidates[0] if self._pace_candidates else None
        if chosen is None:
            unsupported = ", ".join(info.oid for info in infos)
            self._pace_discovery_problem = f"no_locally_supported_pace_profile: {unsupported}"
            if mandatory:
                raise NoSupportedPACEInfo(
                    f"No supported PACEInfo found in EF.CardAccess. Chip advertised: {unsupported}.",
                    mechanism="PACE",
                )
            logging.info(
                "No PACEInfo OID in EF.CardAccess is supported (advertised: %s); falling back to BAC.",
                unsupported,
            )
            return None

        return chosen

    def _select_emrtd_application(self):
        try:
            self._iso7816.select_dedicated_file(EMRTD_AID)
        except ISO7816Exception as exc:
            raise AccessControlNegotiationError(
                f"Could not select the eMRTD application (AID {EMRTD_AID}): "
                f"SW={(exc.sw1 or 0):02X}{(exc.sw2 or 0):02X} ({exc.data}).",
                sw1=exc.sw1,
                sw2=exc.sw2,
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
    (no tag, no length). This matches what ``iso7816.mse_set_at`` expects.
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
