"""Lazy action catalog exposed through the MCP's three small front-door tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _object(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


def _string(description: str, *, enum: tuple[str, ...] = (), default: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "description": description}
    if enum:
        result["enum"] = list(enum)
    if default is not None:
        result["default"] = default
    return result


def _integer(description: str, *, default: int | None = None, minimum: int | None = None, maximum: int | None = None):
    result: dict[str, Any] = {"type": "integer", "description": description}
    if default is not None:
        result["default"] = default
    if minimum is not None:
        result["minimum"] = minimum
    if maximum is not None:
        result["maximum"] = maximum
    return result


def _boolean(description: str, default: bool) -> dict[str, Any]:
    return {"type": "boolean", "description": description, "default": default}


def _credentials() -> dict[str, Any]:
    return {
        "mrz": {
            "description": "Full valid 44- or 60-character MRZ, or [document number, YYMMDD birth, YYMMDD expiry].",
            "oneOf": [
                {"type": "string"},
                {
                    "type": "array",
                    "items": {"type": "string"},
                    "prefixItems": [{"type": "string"}, {"type": "string"}, {"type": "string"}],
                    "minItems": 3,
                    "maxItems": 3,
                },
            ],
        },
        "can": _string("Optional Card Access Number for PACE."),
    }


@dataclass(frozen=True)
class ActionSpec:
    name: str
    group: str
    summary: str
    description: str
    input_schema: dict[str, Any]
    card_effect: str = "read-only"
    example: dict[str, Any] | None = None

    def compact(self) -> dict[str, str]:
        return {"name": self.name, "summary": self.summary, "card_effect": self.card_effect}

    def detailed(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "group": self.group,
            "summary": self.summary,
            "description": self.description,
            "input_schema": self.input_schema,
            "card_effect": self.card_effect,
            "example": self.example or {},
            "invoke": {"tool": "epassport_call", "arguments": {"action": self.name, "arguments": self.example or {}}},
        }


MODE = ("auto", "pace", "bac", "none")
CHANNEL = ("current", "plaintext", "wire")
FUZZ_STRATEGIES = (
    "header_boundary",
    "cla_sweep",
    "ins_sweep",
    "p1_sweep",
    "p2_sweep",
    "le_boundary",
    "length_edge",
    "data_bitflip",
    "tlv_length",
    "payload_length",
    "oversized_payload",
    "extended_encoding",
    "sfi_sweep",
    "data_word_sweep",
)


SPECS = (
    ActionSpec(
        "reader.list",
        "session",
        "List PC/SC NFC readers.",
        "Use first to resolve a reader selector without opening or resetting a card.",
        _object({}),
        example={},
    ),
    ActionSpec(
        "session.connect",
        "session",
        "Attach to ePassportViewer's selected reader.",
        "The GUI owns the PC/SC connection; choose another reader in ePassportViewer rather than opening one "
        "headlessly.",
        _object(
            {
                "reader": {
                    "description": "Zero-based reader index or exact name; omit for the first reader.",
                    "oneOf": [{"type": "integer", "minimum": 0}, {"type": "string"}],
                },
            }
        ),
        card_effect="connect/reset",
        example={},
    ),
    ActionSpec(
        "session.status",
        "session",
        "Inspect reader, access-control, cache, and Secure Messaging state.",
        "This does not send an APDU. Check it after errors to decide whether to reset or re-authenticate.",
        _object({}),
        example={},
    ),
    ActionSpec(
        "session.authenticate",
        "session",
        "Establish BAC, PACE, automatic access control, or a plaintext eMRTD session.",
        "Uses the existing viewer connection and defaults to the MRZ/CAN visible in the GUI. Credentials are retained "
        "only in process "
        "memory for reset_kind=reauth and are never included in status or exported captures.",
        _object(
            {
                **_credentials(),
                "access_control": _string("Mechanism to run.", enum=MODE, default="auto"),
                "reset_before": _boolean("Reset the card before starting the protocol.", True),
            }
        ),
        card_effect="authentication/reset",
        example={"access_control": "auto"},
    ),
    ActionSpec(
        "session.reset",
        "session",
        "Reset, reselect, or reset and re-authenticate the card.",
        "raw leaves the card after ATR with no AID/SM; emrtd selects the application in plaintext; "
        "reauth repeats the last credentials and chosen mechanism. A reset always discards local SM state.",
        _object(
            {
                "kind": _string("Reset behavior.", enum=("raw", "emrtd", "reauth"), default="raw"),
                "access_control": _string("Override retained mode for reauth.", enum=MODE),
                "clear_cache": _boolean("Also forget parsed passport files.", False),
            }
        ),
        card_effect="reset/authentication",
        example={"kind": "reauth", "clear_cache": False},
    ),
    ActionSpec(
        "session.close",
        "session",
        "Disconnect the card and clear live protocol state.",
        "The APDU history and offline case files remain available until cleared/imported.",
        _object({"clear_history": _boolean("Also clear captured APDU traffic.", False)}),
        card_effect="disconnect",
        example={},
    ),
    ActionSpec(
        "apdu.transmit",
        "transport",
        "Send an APDU and receive clear and wire responses.",
        "current accepts a valid short cleartext APDU and uses live BAC/PACE SM; plaintext bypasses SM for one APDU; "
        "wire sends exact bytes, including malformed/already-protected frames. wire defaults to invalidating local SM "
        "because its SSC cannot be synchronized automatically.",
        _object(
            {
                "apdu_hex": _string("Exact command APDU hexadecimal; whitespace and colons are ignored."),
                "channel": _string("Transport layer to use.", enum=CHANNEL, default="current"),
                "invalidate_sm": _boolean("Drop local SM after a wire exchange.", True),
            },
            ("apdu_hex",),
        ),
        card_effect="arbitrary APDU",
        example={"apdu_hex": "00A4040C07A0000002471001", "channel": "current"},
    ),
    ActionSpec(
        "apdu.history",
        "transport",
        "Page through cleartext and exact wire APDU history.",
        "Use after normal, authentication, attack, or fuzz operations. offset is zero-based; "
        "use negative offsets for the most recent records.",
        _object(
            {
                "offset": _integer("First record index; negative means relative to the end.", default=-20),
                "limit": _integer("Maximum records returned.", default=20, minimum=1, maximum=500),
                "include_wire": _boolean("Return exact protected/raw frames as well as clear APDUs.", True),
            }
        ),
        example={"offset": -20, "limit": 20},
    ),
    ActionSpec(
        "apdu.clear_history",
        "transport",
        "Clear in-process APDU history.",
        "Does not affect the current card or Secure Messaging channel.",
        _object({}),
        card_effect="local state",
        example={},
    ),
    ActionSpec(
        "passport.capture",
        "passport",
        "Read EF.CardAccess, EF.COM, declared data groups, and EF.SOD.",
        "With no file list, discovers the chip inventory from COM then reads all declared files. "
        "Returns compact metadata and errors; use passport.read_file/file_chunk for detailed evidence.",
        _object(
            {
                "files": {"type": "array", "items": {"type": "string"}, "description": "Explicit logical file names."},
                "include_card_access": _boolean("Read MF-level EF.CardAccess.", True),
                "include_sod": _boolean("Read EF.SOD.", True),
                "refresh": _boolean("Ignore cached parsed files and reacquire.", False),
            }
        ),
        card_effect="read APDUs",
        example={},
    ),
    ActionSpec(
        "passport.read_file",
        "passport",
        "Read and parse one LDS elementary file.",
        "Returns metadata by default. parsed omits huge binary values after max_binary_bytes; raw returns an exact "
        "requested file slice.",
        _object(
            {
                "name": _string("Logical name: CardAccess, COM, SOD, DG1...DG16, or a known tag."),
                "view": _string(
                    "Response representation.", enum=("summary", "parsed", "raw", "both"), default="parsed"
                ),
                "refresh": _boolean("Re-read instead of using cache.", False),
                "raw_offset": _integer("Raw file byte offset.", default=0, minimum=0),
                "raw_length": _integer("Raw bytes returned for raw/both.", default=4096, minimum=1, maximum=65536),
                "max_binary_bytes": _integer(
                    "Inline parsed binary values at or below this size.", default=256, minimum=0, maximum=65536
                ),
            },
            ("name",),
        ),
        card_effect="read APDUs",
        example={"name": "CardAccess", "view": "parsed"},
    ),
    ActionSpec(
        "passport.file_chunk",
        "passport",
        "Get an exact hex chunk from a captured elementary file.",
        "Useful for DER/TLV analysis without putting an entire biometric or certificate file into the model context.",
        _object(
            {
                "name": _string("Cached file name."),
                "offset": _integer("Byte offset.", default=0, minimum=0),
                "length": _integer("Maximum bytes.", default=4096, minimum=1, maximum=65536),
            },
            ("name",),
        ),
        example={"name": "SOD", "offset": 0, "length": 4096},
    ),
    ActionSpec(
        "passport.inventory",
        "passport",
        "List cached/live case files and their hashes, sizes, and parse anomalies.",
        "No APDUs are sent. Use this before fetching individual evidence.",
        _object({}),
        example={},
    ),
    ActionSpec(
        "passport.filesystem",
        "passport",
        "Enumerate eMRTD applications and probe application-qualified files.",
        "Reads EF.DIR, then uses explicit application/FID context so colliding EF.SOD/EF.CardSecurity and "
        "DG1/EF.DIR identifiers cannot be confused.",
        _object(
            {
                "application": _string("AID in hexadecimal or MF; omit to enumerate every discovered application."),
                "extra_fids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional four-hex-digit FIDs to probe.",
                    "maxItems": 256,
                },
            }
        ),
        card_effect="bounded SELECT/READ APDUs",
        example={},
    ),
    ActionSpec(
        "security.discover_files",
        "security",
        "Boundedly scan FIDs and SFIs for non-advertised files and applets.",
        "Starts with EF.DIR/known ICAO files, adds caller-bounded FID ranges, and optionally sends direct short-file "
        "reads. Results retain response status and data fingerprints without assuming that an unknown file is an "
        "LDS DG.",
        _object(
            {
                "application": _string("Application AID or MF.", default="A0000002471001"),
                "fid_start": _string("First FID in an optional inclusive scan range."),
                "fid_end": _string("Last FID in an optional inclusive scan range."),
                "probe_sfi": _boolean("Probe direct READ BINARY for SFI 1..31.", True),
                "read_data": _boolean(
                    "For selected candidates, read a small prefix instead of selection evidence only.", True
                ),
                "probe_bytes": _integer(
                    "Maximum bytes returned/read per candidate.", default=16, minimum=1, maximum=256
                ),
                "max_probes": _integer("Global bounded probe budget.", default=512, minimum=1, maximum=4096),
            }
        ),
        card_effect="bounded SELECT and READ APDUs",
        example={"application": "A0000002471001", "fid_start": "0100", "fid_end": "01FF"},
    ),
    ActionSpec(
        "passport.read_by_fid",
        "passport",
        "Read an explicit application-qualified FID.",
        "Use after passport.filesystem for files not present in the LDS registry. Reads are bounded and the default "
        "response returns metadata plus a limited hex prefix.",
        _object(
            {
                "application": _string("Application AID in hexadecimal or MF."),
                "fid": _string("Exactly four hexadecimal FID characters."),
                "sfi": _integer("Optional short-file identifier.", minimum=1, maximum=31),
                "maximum": _integer("Maximum permitted EF size.", default=1048576, minimum=1, maximum=16777216),
                "raw_offset": _integer("Returned raw offset.", default=0, minimum=0),
                "raw_length": _integer("Maximum returned bytes.", default=4096, minimum=1, maximum=65536),
            },
            ("application", "fid"),
        ),
        card_effect="bounded SELECT/READ APDUs",
        example={"application": "A0000002471001", "fid": "0101"},
    ),
    ActionSpec(
        "passport.verify",
        "security",
        "Run Active Authentication, SOD trust verification, and DG integrity checks.",
        "All requested checks are attempted independently and structured errors are preserved. "
        "SOD trust requires a CSCA directory containing a Master List or certificates; DG integrity does not.",
        _object(
            {
                "active_authentication": _boolean("Challenge the chip against DG15.", True),
                "data_group_integrity": _boolean("Compare cached/read DG hashes with SOD.", True),
                "sod_certificate": _boolean("Verify SOD signature and DSC-to-CSCA chain.", False),
                "csca_directory": _string("Directory containing CSCA certificates."),
                "master_list_signer_paths": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
            }
        ),
        card_effect="read/authentication APDUs",
        example={"active_authentication": True, "data_group_integrity": True},
    ),
    ActionSpec(
        "security.chip_authentication",
        "security",
        "Run Chip Authentication v1/v2 and confirm the fresh channel keys.",
        "Uses only an SOD-verified DG14 or authenticated EF.CardSecurity. A successful operation replaces the current "
        "Secure Messaging keys and verifies possession through the first protected response.",
        _object(
            {
                "source": _string("Authenticated key source.", enum=("DG14", "CardSecurity"), default="DG14"),
                "key_id": _integer("Optional CA key identifier.", minimum=0),
                "csca_directory": _string("Trust store used for DG14/CardSecurity authentication."),
                "master_list_signer_paths": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
            }
        ),
        card_effect="Chip Authentication and SM re-key",
        example={"source": "DG14"},
    ),
    ActionSpec(
        "security.access_matrix",
        "security",
        "Compare file access across access-control states and addressing paths.",
        "Probes FID/SFI/odd-READ-BINARY under reset, current, PACE, BAC, and optionally CA states. "
        "Each cell records select versus read status and pass/fail/inconclusive outcomes; plaintext probes are "
        "by reauthentication.",
        _object(
            {
                "states": {
                    "type": "array", "maxItems": 8,
                    "items": {
                        "type": "string",
                        "enum": ["raw", "aid", "none", "current", "pace", "bac", "pace_ca", "pace_ca_ta"],
                    },
                },
                "files": {"type": "array", "maxItems": 32, "items": {"type": "string"}},
                "paths": {
                    "type": "array", "maxItems": 5,
                    "items": {"type": "string", "enum": ["fid", "sfi", "odd_sfi", "plaintext_fid", "plaintext_sfi"]},
                },
                "probe_bytes": _integer("Maximum response prefix per cell.", default=8, minimum=1, maximum=256),
                "max_probes": _integer("Global bounded cell budget.", default=256, minimum=1, maximum=1024),
                "csca_directory": _string("Strict trust-store directory for pace_ca."),
                "master_list_signer_paths": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
                "terminal_chain_paths": {"type": "array", "maxItems": 8, "items": {"type": "string"}},
                "terminal_private_key_path": _string("Terminal private key for pace_ca_ta."),
                "terminal_trust_anchor_paths": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
                "id_picc_hex": _string("Document-derived ID_PICC for pace_ca_ta."),
                "restore_after": _boolean("Restore the retained authenticated state afterward.", True),
            }
        ),
        card_effect="reset/authentication and bounded read APDUs",
        example={"states": ["raw", "aid", "current"], "files": ["DG1", "DG3"], "paths": ["fid", "plaintext_fid"]},
    ),
    ActionSpec(
        "security.aa_analysis",
        "security",
        "Validate AA and check chosen-challenge nonce and pre-access behavior.",
        "Uses DG15/DG14 to verify ECDSA responses, samples distinct challenges for repeated r values, and tests "
        "whether "
        "INTERNAL AUTHENTICATE is exposed before BAC/PACE. It does not and cannot export the chip private key.",
        _object(
            {
                "rounds": _integer("Distinct post-access challenges.", default=8, minimum=2, maximum=256),
                "test_pre_access": _boolean("Try INTERNAL AUTHENTICATE after a reset before access control.", True),
                "restore_after": _boolean("Restore retained access control afterward.", True),
            }
        ),
        card_effect="reset, INTERNAL AUTHENTICATE, and reauthentication APDUs",
        example={"rounds": 8},
    ),
    ActionSpec(
        "security.terminal_authentication",
        "security",
        "Validate and perform EAC Terminal Authentication.",
        "Loads the IS/DV CVC chain, terminal private key, and explicit CVCA trust anchors from local files. "
        "also confirms that DG3/DG4 rights omitted by CHAT remain denied.",
        _object(
            {
                "terminal_chain_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Leaf-first CVC certificate file paths.",
                    "minItems": 1,
                },
                "private_key_path": _string("Terminal RSA/EC private key file."),
                "trust_anchor_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit CVCA CVC trust anchor file paths.",
                    "minItems": 1,
                },
                "id_picc_hex": _string("Document-derived ID_PICC hexadecimal."),
                "cvca_references_hex": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Current/previous EF.CVCA references; omit to read EF.CVCA.",
                    "maxItems": 2,
                },
                "test_negative_rights": _boolean("Probe ungranted DG3/DG4 access.", True),
            },
            ("terminal_chain_paths", "private_key_path", "trust_anchor_paths", "id_picc_hex"),
        ),
        card_effect="Terminal Authentication and protected biometric probes",
        example={
            "terminal_chain_paths": ["/path/is.cvc", "/path/dv.cvc"],
            "private_key_path": "/path/is-key.der",
            "trust_anchor_paths": ["/path/cvca.cvc"],
            "id_picc_hex": "0102030405060708",
        },
    ),
    ActionSpec(
        "security.conformance",
        "security",
        "Run a redacted BSI TR-03105-oriented interoperability profile.",
        "Runs required LDS, access-control, filesystem and optional authenticity/CA checks. The output contains no "
        "credentials, raw document contents, exact APDUs, ATR, UID, challenges, keys, or certificate identities.",
        _object(
            {
                "name": _string("Profile/report name."),
                "required_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Logical files required by the issuer profile.",
                    "maxItems": 32,
                },
                "allowed_access_controls": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["pace", "bac", "none", "PACE", "BAC", "NONE"]},
                    "description": "Accepted mechanisms (case-sensitive values are normalized).",
                    "maxItems": 3,
                },
                "allowed_pace_oids": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
                "forbid_bac_downgrade": _boolean("Fail an explicit PACE-to-BAC downgrade.", True),
                "reject_parse_errors": _boolean("Fail structurally anomalous required files.", True),
                "verify_data_group_integrity": _boolean("Check requested DG hashes against SOD.", True),
                "verify_sod_signature": _boolean("Validate DSC/CSCA trust.", False),
                "verify_active_authentication": _boolean("Run AA.", False),
                "verify_chip_authentication": _boolean("Run CA.", False),
                "chip_authentication_source": _string("CA key source.", enum=("DG14", "CardSecurity"), default="DG14"),
                "chip_authentication_key_id": _integer("Optional CA key identifier.", minimum=0),
                "enumerate_file_system": _boolean("Enumerate/probe application files.", True),
                "application": _string("Application AID or MF."),
                "extra_fids": {"type": "array", "items": {"type": "string"}, "maxItems": 256},
                "csca_directory": _string("CSCA/Master List directory for trust checks."),
            }
        ),
        card_effect="bounded read/authentication APDUs",
        example={"name": "modern issuer", "allowed_access_controls": ["PACE"]},
    ),
    ActionSpec(
        "security.audit",
        "security",
        "Build an evidence-backed security posture report from captured files and live checks.",
        "This report detects weak/legacy access control, absent/failed authenticity checks, "
        "unhashed/undeclared files, structural anomalies, and advertised protocol capabilities. "
        "capture_missing can run the normal acquisition first.",
        _object(
            {
                "capture_missing": _boolean("Capture COM, SOD and declared files first.", False),
                "run_live_checks": _boolean("Run AA and DG integrity before reporting.", True),
                "verify_sod_certificate": _boolean("Also validate SOD/DSC trust; requires csca_directory.", False),
                "csca_directory": _string("Directory containing CSCA certificates."),
                "master_list_signer_paths": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
                "probe_uid": _boolean("Try vendor GET UID; often unavailable for passports.", False),
                "detail": _string(
                    "summary returns findings; full also returns protocol/file details.",
                    enum=("summary", "full"),
                    default="full",
                ),
            }
        ),
        card_effect="optional read/authentication APDUs",
        example={"capture_missing": False, "run_live_checks": True, "detail": "full"},
    ),
    ActionSpec(
        "fuzz.run",
        "research",
        "Run a deterministic bounded APDU mutation campaign.",
        "Stores complete results server-side and returns only the summary plus selected interesting cases. "
        "Reauthentication reset policy uses retained credentials.",
        _object(
            {
                "seed_apdu_hex": _string("Valid short APDU used as the mutation seed."),
                "strategies": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(FUZZ_STRATEGIES)},
                    "description": "Omit for boundary defaults.",
                },
                "max_cases": _integer("Unique cases including baseline.", default=256, minimum=1, maximum=10000),
                "repeat_each": _integer("Executions per case.", default=1, minimum=1, maximum=100),
                "delay_ms": _integer("Delay between executions.", default=0, minimum=0, maximum=60000),
                "channel": _string(
                    "current mutates the inner command under valid live SM; plaintext bypasses SM; wire mutates exact "
                    "framing.",
                    enum=("current", "plaintext", "wire"),
                    default="current",
                ),
                "safety_profile": _string(
                    "read_only accepts only known non-persistent inner instructions; research permits unknown/wire "
                    "commands.",
                    enum=("read_only", "research"),
                    default="read_only",
                ),
                "reset_policy": _string(
                    "When to reset.", enum=("never", "before_campaign", "before_each", "on_error"), default="never"
                ),
                "reset_kind": _string(
                    "raw reset or reset plus retained access control.", enum=("raw", "reauth"), default="raw"
                ),
                "include_state_changing": _boolean("Allow generated INS values such as VERIFY/UPDATE/ERASE.", False),
                "recover_after": _boolean("Reset/re-authenticate after the campaign.", True),
                "interesting_limit": _integer(
                    "Interesting cases included immediately.", default=20, minimum=0, maximum=100
                ),
            },
            ("seed_apdu_hex",),
        ),
        card_effect="generated APDUs/reset",
        example={"seed_apdu_hex": "00A4020C020101", "max_cases": 128, "channel": "current"},
    ),
    ActionSpec(
        "fuzz.results",
        "research",
        "Page through the latest fuzz campaign.",
        "Use interesting_only to avoid filling context with baseline-equivalent cases.",
        _object(
            {
                "offset": _integer("Zero-based offset into filtered results.", default=0, minimum=0),
                "limit": _integer("Maximum results.", default=50, minimum=1, maximum=500),
                "interesting_only": _boolean("Return only anomalies, errors, and outliers.", True),
            }
        ),
        example={"interesting_only": True},
    ),
    ActionSpec(
        "attack.mac_traceability",
        "research",
        "Test the Chothia-Smirnov BAC MAC traceability weakness.",
        "Establishes legitimate BAC, compares wrong/correct MAC behavior, and resets between trials. "
        "The retained MRZ is used unless supplied.",
        _object({**_credentials(), "cutoff_ms": {"type": "number", "minimum": 0, "default": 1.7}}),
        card_effect="authentication/invalid APDUs/reset",
        example={"cutoff_ms": 1.7},
    ),
    ActionSpec(
        "attack.aa_before_access",
        "research",
        "Test whether Active Authentication works before access control.",
        "Resets then sends INTERNAL AUTHENTICATE without BAC/PACE. A signature response indicates traceability "
        "exposure.",
        _object({}),
        card_effect="authentication APDU/reset",
        example={},
    ),
    ActionSpec(
        "attack.sign_challenge",
        "research",
        "Use Active Authentication as an arbitrary 64-bit signing oracle.",
        "Optionally verifies the signature against DG15, which requires retained/provided MRZ credentials.",
        _object(
            {
                "challenge_hex": _string("Exactly 8 bytes (16 hex characters)."),
                "verify_with_dg15": _boolean("Re-authenticate/read DG15 and verify the result.", False),
                **_credentials(),
            },
            ("challenge_hex",),
        ),
        card_effect="authentication APDU/reset",
        example={"challenge_hex": "1122334455667788", "verify_with_dg15": False},
    ),
    ActionSpec(
        "attack.aa_traceability",
        "research",
        "Collect the highest pre-access RSA AA signature as a modulus lower bound.",
        "Repeatedly challenges a passport that permits AA before access control. "
        "Compare with attack.aa_compare or read DG15.",
        _object({"rounds": _integer("Random challenges.", default=100, minimum=1, maximum=100000)}),
        card_effect="authentication APDUs/reset",
        example={"rounds": 100},
    ),
    ActionSpec(
        "attack.aa_compare",
        "research",
        "Compare an observed signature lower bound to a candidate RSA modulus.",
        "Offline computation; if highest_signature exceeds modulus they cannot belong to the same passport.",
        _object(
            {
                "modulus_hex": _string("Candidate DG15 RSA modulus."),
                "highest_signature_hex": _string("Observed bound."),
            },
            ("modulus_hex", "highest_signature_hex"),
        ),
        example={"modulus_hex": "A1B2", "highest_signature_hex": "90FF"},
    ),
    ActionSpec(
        "attack.bac_bruteforce",
        "research",
        "Run bounded online or offline BAC credential search ranges.",
        "Offline takes a captured 40-byte mutual-authentication message/MAC and never contacts a card. "
        "Online tests each candidate on the connected chip; narrow the ranges deliberately.",
        _object(
            {
                "mode": _string("Execution mode.", enum=("online", "offline")),
                "captured_pair_hex": _string("Required for offline mode: encrypted message plus MAC."),
                "document_number_low": _string("Inclusive value."),
                "document_number_high": _string("Inclusive value; defaults to low."),
                "date_of_birth_low": _string("Inclusive YYMMDD."),
                "date_of_birth_high": _string("Inclusive YYMMDD; defaults to low."),
                "expiry_low": _string("Inclusive YYMMDD."),
                "expiry_high": _string("Inclusive YYMMDD; defaults to low."),
                "reset_each": _boolean("Reset between online attempts.", True),
            },
            ("mode", "document_number_low", "date_of_birth_low", "expiry_low"),
        ),
        card_effect="credential guesses/reset",
        example={
            "mode": "offline",
            "captured_pair_hex": "...",
            "document_number_low": "L898902C3",
            "date_of_birth_low": "740812",
            "expiry_low": "120415",
        },
    ),
    ActionSpec(
        "case.import_snapshot",
        "case",
        "Load an ePassportViewer v3 JSON research snapshot for offline analysis.",
        "Imports raw EFs and APDU history, disconnecting any live session. Credentials in the file are intentionally "
        "ignored by the MCP.",
        _object(
            {"path": _string("Local snapshot JSON path."), "replace_history": _boolean("Replace APDU history.", True)},
            ("path",),
        ),
        card_effect="local state",
        example={"path": "/absolute/path/passport-session.json"},
    ),
    ActionSpec(
        "case.export_snapshot",
        "case",
        "Export raw cached EFs, capture metadata, checks, and APDU history.",
        "Writes an ePassportViewer-compatible v3 JSON snapshot. Credentials are never written by this MCP.",
        _object({"path": _string("Local destination JSON path.")}, ("path",)),
        card_effect="local file write",
        example={"path": "/absolute/path/passport-session.json"},
    ),
)

ACTION_SPECS = {spec.name: spec for spec in SPECS}
GROUPS = tuple(sorted({spec.group for spec in SPECS}))
