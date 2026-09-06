from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pypassport import ca_manager
from pypassport.doc9303 import converter, secure_messaging
from pypassport.doc9303.access_control import (
    EMRTD_AID,
    MODE_AUTO,
    AccessControlNegotiationError,
    AccessControlNegotiator,
    NegotiationResult,
)
from pypassport.doc9303.active_authentication import ActiveAuthentication, ActiveAuthenticationException
from pypassport.doc9303.bac import BAC, BACException
from pypassport.doc9303.data_group import DataGroupDump, ElementaryFileException, read_elementary_file
from pypassport.doc9303.mrz import MRZ
from pypassport.doc9303.pace import PACE
from pypassport.doc9303.file_context import resolve_file
from pypassport.doc9303.chip_authentication import ChipAuthentication, select_chip_authentication_pair
from pypassport.doc9303.security_info import parse_security_infos
from pypassport.doc9303.trust_store import TrustStore
from pypassport.doc9303.terminal_authentication import TerminalAuthentication, parse_ef_cvca, validate_cvc_chain
from pypassport.doc9303.file_system import FileSystemExplorer
from pypassport.doc9303.passive_authentication import PassiveAuthentication, PassiveAuthenticationException
from pypassport.iso7816 import ISO7816, ISO7816Exception
from pypassport.reader import is_no_card_exception


class EPassportException(Exception):
    pass


class DataGroupException(Exception):
    pass


class EPassport(dict):
    """
    High-level class encapsulating communication with an ePassport chip.

    Implemented as a dictionary: data groups are read on first access and
    cached. Supports BAC/PACE secure messaging, active authentication, and
    passive authentication.

    @param reader: A reader object (RFID reader) or a path string (simulator).
    @param epMrz: The passport MRZ string or tuple used for BAC key derivation.
    """

    def __init__(self, reader, epMrz=None, *, select_aid=True):
        """
        Initialise the ePassport object.

        @param reader: A reader object, or an existing :class:`ISO7816`
            transport when attaching high-level operations to a low-level
            research session.
        @param epMrz: MRZ string/tuple. Required for BAC; optional otherwise.
        @param select_aid: If True (default), select the eMRTD application
            immediately after connecting. Set to False when the caller plans
            to drive access control via :meth:`open`, which will select the
            AID itself after the chosen mechanism (PACE or BAC) has run.
        @raise EPassportException: If the MRZ is invalid, no passport is
            present, or the chip does not contain an eMRTD applet.
        """

        self._mrz: MRZ | None
        if epMrz:
            self._mrz = epMrz if isinstance(epMrz, MRZ) else MRZ(epMrz)
            if not self._mrz.check_mrz():
                raise EPassportException("Invalid MRZ")
        else:
            self._mrz = None

        if isinstance(reader, ISO7816):
            self.iso7816 = reader
        else:
            try:
                reader.connect()
            except Exception as exc:
                if is_no_card_exception(exc):
                    raise EPassportException("No passport present on the reader") from exc
                raise

            self.iso7816 = ISO7816(reader)
        self._bac = BAC(self.iso7816)
        self._pace = PACE(self.iso7816, self._mrz)
        self._aa = ActiveAuthentication(self.iso7816)
        self._pa = PassiveAuthentication()
        self._ca = ChipAuthentication(self.iso7816)
        self._ta = TerminalAuthentication(self.iso7816)
        self.file_system = FileSystemExplorer(self.iso7816)
        self._trust_store: TrustStore | None = None
        self._CSCADirectory: ca_manager.CAManager | None = None
        self._access_control: NegotiationResult | None = None
        # EF.CardAccess lives under the MF, while normal EPassport reads live
        # under the eMRTD application. Keep track of the intended context so a
        # CardAccess read can restore it before later DG reads continue.
        self._emrtd_selected = False
        # Remember the credentials/mode the session was last opened with so a
        # lazy read can re-establish Secure Messaging the same way without the
        # caller re-supplying them (see ensure_open / _read).
        self._can: str | None = None
        self._ac_mode = MODE_AUTO
        self._allow_bac_fallback = False

        if select_aid:
            # Select eMRTD Dedicated File (DF) with AID = A0000002471001
            try:
                self.iso7816.select_dedicated_file("A0000002471001")
                self._emrtd_selected = True
            except ISO7816Exception:
                raise EPassportException("The chip does not contain eMRTD applet")

    @property
    def access_control(self):
        """The NegotiationResult from the last successful :meth:`open` call."""
        return self._access_control

    def open(self, mrz=None, access_control=MODE_AUTO, can=None, *, pin=None, puk=None, password=None, allow_bac_fallback=False):
        """
        Set up secure messaging via PACE or BAC, then select the eMRTD AID.

        This is the recommended entry point for reading a passport. It
        inspects ``EF.CardAccess`` (when allowed) to pick the best mechanism,
        runs it, and leaves the chip selected on the eMRTD application
        ready for reading EF.COM, EF.SOD, DG1, DG2, etc.

        @param mrz: An MRZ string/tuple/object. If not provided, the MRZ
            supplied to ``__init__`` is used.
        @param access_control: One of ``"auto"``, ``"pace"``, ``"bac"``,
            ``"none"``. See :class:`AccessControlNegotiator` for semantics.
        @param can: Optional Card Access Number printed on the document.
            When supplied, PACE is attempted with the CAN (password
            reference 0x02) instead of (or in addition to) the MRZ.
        @return: The :class:`NegotiationResult` describing what ran.
        @raise EPassportException: If access control fails or required
            credentials are missing.
        """
        if mrz is not None:
            new_mrz = MRZ(mrz) if not isinstance(mrz, MRZ) else mrz
            if not new_mrz.check_mrz():
                raise EPassportException("Invalid MRZ")
            self._mrz = new_mrz

        if can is not None and isinstance(can, str):
            can = can.strip() or None

        self._can = can
        self._ac_mode = access_control
        self._allow_bac_fallback = allow_bac_fallback
        self._pace = PACE(self.iso7816, mrz=self._mrz, can=can)

        try:
            result = AccessControlNegotiator(self.iso7816).open(
                self._mrz,
                mode=access_control,
                can=can,
                pin=pin,
                puk=puk,
                password=password,
                allow_bac_fallback=allow_bac_fallback,
            )
        except AccessControlNegotiationError as exc:
            raise EPassportException(str(exc)) from exc

        self._access_control = result
        if result.card_security is not None:
            self.__setitem__("CardSecurity", result.card_security)
        self._emrtd_selected = True
        return result

    def ensure_open(self, mrz=None, access_control=None, can=None, *, allow_bac_fallback=None):
        """Open the session only if no Secure Messaging channel is active yet.

        Idempotent counterpart to :meth:`open`, intended for a passport object
        shared across callers. When a Secure Messaging channel is already in
        place — typically because another part of the application already
        opened this session — it returns the previous :class:`NegotiationResult`
        without touching the card, so the cached data groups are reused and
        PACE/BAC is not run again. Otherwise it falls back to :meth:`open`,
        defaulting the access-control mode and CAN to whatever the session was
        last opened (or initialised) with.

        @return: The :class:`NegotiationResult` describing the live (or newly
            established) channel.
        @raise EPassportException: If access control has to run and fails or
            required credentials are missing.
        """
        if self.iso7816.ciphering is not None and self._access_control is not None:
            return self._access_control
        kwargs = {
            "mrz": mrz,
            "access_control": self._ac_mode if access_control is None else access_control,
            "can": self._can if can is None else can,
        }
        configured_fallback = getattr(self, "_allow_bac_fallback", None)
        if allow_bac_fallback is not None or configured_fallback is not None:
            kwargs["allow_bac_fallback"] = configured_fallback if allow_bac_fallback is None else allow_bac_fallback
        return self.open(**kwargs)

    @property
    def csca_directory(self):
        return self._CSCADirectory

    @csca_directory.setter
    def csca_directory(self, value):
        self._CSCADirectory = ca_manager.CAManager(value)

    @property
    def trust_store(self):
        return self._trust_store

    @trust_store.setter
    def trust_store(self, value):
        if not isinstance(value, TrustStore):
            raise TypeError("trust_store must be an ICAO TrustStore")
        self._trust_store = value

    def rst_connection(self):
        logging.debug("Reset Connection")
        result = self.iso7816.rst_connection()
        self._emrtd_selected = True
        return result

    def do_basic_access_control(self):
        """
        Execute the Basic Access Control protocol and set up secure messaging.

        @raise EPassportException: If the MRZ is not initialised, the chip
            rejects the BAC keys (likely incorrect MRZ), or any other low-level
            communication failure occurs during the BAC protocol.
        """
        logging.info("Basic Access Control: Enabling Secure Messaging")
        if self._mrz is None:
            logging.warning("No MRZ provided")
            raise EPassportException("The object must be initialized with the ePassport MRZ")

        try:
            (KSenc, KSmac, ssc) = self._bac.authentication_and_establishment_of_session_keys(self._mrz)
        except BACException as e:
            raise EPassportException(str(e)) from e
        except ISO7816Exception as e:
            raise EPassportException(f"BAC failed: chip returned {e.sw1:02X}{e.sw2:02X} ({e.data}).") from e

        sm = secure_messaging.SecureMessaging(KSenc, KSmac, ssc)
        self.iso7816.ciphering = sm

    def do_active_authentication(self, dg15=None, *, strict=True):
        """
        Execute the Active Authentication protocol.

        @return: True if authentication succeeds.
        @raise DataGroupException: If DG15 cannot be read.
        @raise ActiveAuthenticationException: On other AA failures.
        """
        logging.info("Active Authentication")
        res: Any = ""
        try:
            if dg15 is None:
                dg15 = self["DG15"]
            # DG14 (when present) names the ECDSA AA hash via its
            # ActiveAuthenticationInfo; it is optional and ignored for RSA keys.
            try:
                dg14 = self["DG14"]
            except Exception:
                dg14 = None
            res = self._aa.execute_aa(dg15, dg14, strict=strict)
            return res
        except ElementaryFileException as msg:
            res = msg
            raise DataGroupException(msg)
        except Exception as msg:
            res = msg
            raise ActiveAuthenticationException(msg)
        finally:
            logging.debug("Active Authentication: " + str(res))

    def do_chip_authentication(self, *, source="DG14", key_id=None):
        """Run CA v1/v2 from SOD-authenticated DG14 or signed CardSecurity."""
        source_name = str(source).upper()
        security_file = self["CardSecurity" if source_name in ("CARDSECURITY", "MF") else "DG14"]
        if security_file is None:
            raise EPassportException(f"Cannot read {source}")
        if source_name in ("CARDSECURITY", "MF"):
            trust = self._trust_store or self._CSCADirectory
            if trust is None:
                raise EPassportException("Authenticated EF.CardSecurity requires a configured trust store")
            security_file.authenticate(trust)
            infos = security_file["security_infos"]
        else:
            # A DG14 key is security-relevant only after both the SOD chain and
            # its own data-group hash have been verified.
            self.do_verify_sod_certificate()
            integrity = self.do_verify_dg_integrity([security_file])
            if not integrity or integrity.get("DG14") is not True:
                raise EPassportException("DG14 failed passive authentication")
            infos = security_file.get("security_infos") or parse_security_infos(security_file.body)
        ca_info, public_key = select_chip_authentication_pair(infos, key_id)
        return self._ca.perform(ca_info, public_key)

    def read_ef_cvca(self, fid=None, *, application=None):
        if fid is None:
            dg14 = dict.get(self, "DG14")
            if dg14:
                infos = dg14.get("security_infos") or []
                fid = next((x.get("ef_cvca_fid") for x in infos if x.get("ef_cvca_fid")), None)
        reference = resolve_file("CVCA")
        if fid is not None or application is not None:
            reference = type(reference)(reference.name, reference.ef_name, application or reference.application,
                                        fid or reference.fid, reference.sfi, reference.tag, reference.parser)
        self.iso7816.select_context(reference)
        return parse_ef_cvca(self.iso7816.read_selected_binary_all(chunk_size=256, maximum=4096))

    def do_terminal_authentication(self, terminal_chain, private_key_der, id_picc, *, cvca_references=None,
                                   trust_anchors=(), test_negative_rights=True, allow_chip_validation_only=False):
        """Validate/send a CVC chain and optionally probe absent CHAT rights."""
        if not terminal_chain or not private_key_der or not id_picc:
            raise EPassportException("TA requires a terminal certificate chain, private key, and ID_PICC")
        if trust_anchors:
            validate_cvc_chain(terminal_chain, trust_anchors)
        elif not allow_chip_validation_only:
            raise EPassportException("TA requires local CVCA trust anchors; set allow_chip_validation_only for protocol-negative testing")
        references = cvca_references or self.read_ef_cvca()
        ca_public = self._ca.result.terminal_public_key if hasattr(self._ca, "result") else b""
        result = self._ta.perform(terminal_chain, private_key_der, references, id_picc,
                                  ca_ephemeral_public_key=ca_public)
        result["locally_validated"] = bool(trust_anchors)
        result["negative_rights"] = []
        if test_negative_rights:
            for allowed, name in ((result["rights"]["read_dg3"], "DG3"), (result["rights"]["read_dg4"], "DG4")):
                if allowed:
                    continue
                try:
                    unexpected = self._read_elementary_file(name)
                except Exception as exc:
                    result["negative_rights"].append({"file": name, "enforced": True, "error": str(exc)})
                else:
                    result["negative_rights"].append({"file": name, "enforced": False,
                                                       "security_issue": f"{name} readable without its CHAT right",
                                                       "bytes": len(unexpected.file)})
        return result

    def do_verify_sod_certificate(self):
        """
        Verify the Document Signer Certificate (first part of passive auth).

        @raise ElementaryFileException: If the SOD cannot be read.
        @raise PassiveAuthenticationException: On PA configuration or verification errors.
        """
        res: Any = ""
        try:
            sod = self.read_sod()
            trust = self._trust_store or self.csca_directory
            if trust is None:
                raise PassiveAuthenticationException("csca_directory/trust_store is not set")
            res = self._pa.verify_sod_and_cds(sod, trust)
            if res and self._access_control is not None and self._access_control.cam_result:
                card_security = self._access_control.card_security
                if card_security is None:
                    raise PassiveAuthenticationException("PACE-CAM CardSecurity evidence was not retained")
                card_security.authenticate(trust)
                self._access_control.cam_result["card_security_signer_trusted"] = True
                self._access_control.cam_result["passive_authentication"] = "complete"
            return res
        except ElementaryFileException as msg:
            res = msg
            raise ElementaryFileException(msg)
        except PassiveAuthenticationException as msg:
            res = msg
            raise PassiveAuthenticationException(msg)
        finally:
            logging.debug("Document Signer Certificate verification: " + str(res))

    @property
    def sod_verification_info(self):
        """Details about the last successful EF.SOD verification."""

        return self._pa.verification_info

    def do_verify_dg_integrity(self, dgs=None):
        """
        Verify data group integrity (second part of passive auth).

        @raise ElementaryFileException: If a data group cannot be read.
        @raise PassiveAuthenticationException: On PA configuration errors.
        """
        res: Any = None
        try:
            sod = self.read_sod()
            if dgs is None:
                dgs = self.read_data_groups()
            res = self._pa.execute_pa(sod, dgs)
            return res
        except ElementaryFileException as msg:
            res = msg
            raise ElementaryFileException(msg)
        except PassiveAuthenticationException as msg:
            res = msg
            raise PassiveAuthenticationException(msg)
        except Exception as msg:
            res = msg
            logging.error("Data group integrity verification failed: " + str(msg))
        finally:
            logging.debug("Data Groups integrity verification: " + str(res))

    def read_sod(self):
        """
        Read the Security Object file (SOD).

        @return: A SOD object.
        """
        return self["SOD"]

    def read_com(self):
        """
        Read the Common file and return the list of data groups present.

        @return: A list of data group tag strings (e.g. ["DG1", "DG2", ...]).
        """
        dg_list = []
        for tag in self["COM"]["5C"]:
            dg_list.append(converter.to_dg(tag))
        return dg_list

    def read_data_groups(self, *, include_unlisted=False):
        """
        Read all data groups listed in the Common file (EF.COM).

        @return: A list of data group objects successfully read.
        """
        dg_list = []
        listed = list(self["COM"]["5C"]) if self["COM"] is not None else []
        if include_unlisted:
            listed.extend(f"DG{i}" for i in range(1, 17))
        for dg in dict.fromkeys(listed):
            try:
                data_group = self[dg]
            except Exception as e:
                logging.warning(f"Could not read {dg}: {e}")
                continue
            if data_group is not None:
                dg_list.append(data_group)
        return dg_list

    def read_passport(self):
        """
        Read the files declared in EF.COM, plus EF.SOD.

        Only the data groups listed in EF.COM are read; any data group not
        declared there is skipped.

        @return: This EPassport instance (dict populated with the declared DGs).
        """
        logging.debug("Reading Passport")
        self.read_com()
        self.read_data_groups()
        self.read_sod()
        return self

    # Dict overwriting
    def __getitem__(self, tag):
        """
        Return the data group object for the given tag, reading it if necessary.

        If a 'Security Status Not Satisfied' error (SW 6982) is returned and
        secure messaging is not yet active, access control (PACE or BAC, chosen
        automatically) is run and the read is retried. Any other failure leaves
        the file reported as unreadable (None).

        @param tag: A tag string such as "DG1", "COM", "SOD", etc.
        @return: The parsed data group object, or None if it could not be read.
        @raise ElementaryFileException: If the tag is unknown.
        """
        try:
            reference = resolve_file(tag)
        except KeyError:
            raise ElementaryFileException("The data group '" + str(tag) + "' does not exist")

        if reference.name in self:
            return super(EPassport, self).__getitem__(reference.name)
        if reference.name != "CardSecurity" and reference.tag in self:
            value = super(EPassport, self).__getitem__(reference.tag)
            self.__setitem__(reference.name, value)
            return value

        dg = self._read(reference)
        if dg is not None:
            self.__setitem__(reference.name, dg)
            if reference.name != "CardSecurity" and dg.tag:
                self.__setitem__(dg.tag, dg)
            return dg
        return None

    def _read(self, tag):
        """
        Read a single elementary file.

        If the chip demands secure messaging (SW 6982) and none is active yet,
        access control is bootstrapped automatically (PACE or BAC, auto-detected
        by :meth:`ensure_open`) and the read retried. Any other failure leaves
        the file unreadable (None).

        @return: The parsed data group object, or None if it could not be read.
        @raise EPassportException: If the bootstrap access-control handshake fails.
        """
        try:
            return self._read_elementary_file(tag)
        except ISO7816Exception as e:
            if self.iso7816.ciphering is None and e.sw1 == 0x69 and e.sw2 == 0x82:
                # Unauthenticated and the chip wants secure messaging: bootstrap
                # access control, then retry. ensure_open auto-detects PACE vs
                # BAC from EF.CardAccess (falling back to BAC) using the stored
                # MRZ/CAN, and raises EPassportException on a bad/missing
                # credential, which intentionally propagates so the caller can
                # show a meaningful error.
                self.ensure_open()
                try:
                    return self._read_elementary_file(tag)
                except ISO7816Exception as e2:
                    sw2_str = f"SW={e2.sw1:02X}{e2.sw2:02X}" if e2.sw1 is not None else ""
                    logging.error(f"Could not read {tag} after BAC: chip returned {sw2_str} ({e2.data})")
                    return None
            sw_str = f"SW={e.sw1:02X}{e.sw2:02X}" if e.sw1 is not None else str(e)
            logging.error(f"Could not read {tag}: chip returned {sw_str} ({e.data})")
            return None
        except EPassportException:
            raise
        except Exception as msg:
            logging.error(f"Could not read {tag}: {msg}")
            return None

    def _read_elementary_file(self, tag):
        """Read one EF while preserving the eMRTD application context.

        EF.CardAccess is selected from the Master File by the MF-aware reader.
        When it is requested through an already-open EPassport session, that
        temporary selection must not leak into the next DG read.
        """

        reference = resolve_file(tag)
        restore_emrtd = getattr(self, "_emrtd_selected", False) and reference.name == "CardAccess"
        try:
            # Keep the resolved application/DF identity intact. Converting it
            # back to an outer tag is lossy (DG1 and EF.DIR are both 0x61;
            # EF.SOD and EF.CardSecurity are both 0x011D/0x77).
            return read_elementary_file(reference, self.iso7816)
        finally:
            if restore_emrtd:
                try:
                    self.iso7816.select_dedicated_file(EMRTD_AID)
                except ISO7816Exception as exc:
                    logging.warning(
                        "Could not restore eMRTD application after reading EF.CardAccess: "
                        "SW=%02X%02X (%s)",
                        exc.sw1 or 0,
                        exc.sw2 or 0,
                        exc.data,
                    )

    def __iter__(self):
        """Iterate over all passport files, reading them first if necessary."""
        self.read_passport()
        return super(EPassport, self).__iter__()

    def get_signatures(self):
        """
        Return a list of signatures from DG7 in binary format.

        @return: A list of binary strings.
        """
        tmp = []
        try:
            dg7 = self["DG7"]
            for tag in ["5F43"]:
                if tag in dg7:
                    for x in dg7[tag]:
                        tmp.append(x)
        except Exception:
            pass
        return tmp

    def get_faces(self):
        """
        Return a list of face images from DG2 in binary format.

        @return: A list of binary strings.
        """
        try:
            dg2 = self["DG2"]
            if dg2 is None:
                return []
            return dg2.get_biometric_data()
        except Exception:
            return []

    def get_certificate(self):
        """
        Extract the Document Signer certificate from the SOD.

        @return: The certificate in human-readable format, or None on error.
        """
        try:
            return self._pa.get_certificate(self.read_sod())
        except Exception:
            return None

    def get_public_key(self):
        """
        Extract the Active Authentication public key from DG15.

        @return: The public key in human-readable format, or None on error.
        """
        try:
            return self._aa.get_pub_key(self["DG15"])
        except Exception:
            return None

    def dump(self, directory=None, extension=".bin"):
        """
        Dump ePassport content to disk, including faces, signatures, the DG15
        public key, and the Document Signer Certificate.

        @param directory: Target directory (default: user home directory).
        @param extension: File extension for data group dumps.
        """
        dgd = DataGroupDump(Path.home() if directory is None else directory, extension)
        dgd.dump(self)

        cpt = 0
        for sig in self.get_signatures():
            dgd.dump_data(sig, "signature" + str(cpt) + ".jpg")
            cpt += 1

        cpt = 0
        for face in self.get_faces():
            dgd.dump_data(face, "face" + str(cpt) + ".jpg")
            cpt += 1

        dgd.dump_data(self.get_public_key(), "DG15PubKey.pk")
        dgd.dump_data(self.get_certificate(), "DocumentSigner.cer")

    def switch_mrz(self, newMRZ):
        currentMRZ = self._mrz
        self._mrz = MRZ(newMRZ)
        if not self._mrz.check_mrz():
            raise EPassportException("Invalid MRZ")
        return str(currentMRZ)
