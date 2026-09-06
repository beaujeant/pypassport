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
        "Connect one reader and create a shared low-level session.",
        "Select by zero-based index or exact PC/SC name. The MCP process owns this connection until session.close.",
        _object(
            {
                "reader": {
                    "description": "Zero-based reader index or exact name; omit for the first reader.",
                    "oneOf": [{"type": "integer", "minimum": 0}, {"type": "string"}],
                },
            }
        ),
        card_effect="connect/reset",
        example={"reader": 0},
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
        "Attaches high-level operations to the existing low-level connection. Credentials are retained only in process "
        "memory for reset_kind=reauth and are never included in status or exported captures.",
        _object(
            {
                **_credentials(),
                "access_control": _string("Mechanism to run.", enum=MODE, default="auto"),
                "reset_before": _boolean("Reset the card before starting the protocol.", True),
            }
        ),
        card_effect="authentication/reset",
        example={"mrz": ["L898902C3", "740812", "120415"], "access_control": "auto"},
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
            }
        ),
        card_effect="read/authentication APDUs",
        example={"active_authentication": True, "data_group_integrity": True},
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
                    "current applies live SM; plaintext bypasses it.", enum=("current", "plaintext"), default="current"
                ),
                "reset_policy": _string(
                    "When to reset.", enum=("never", "before_campaign", "before_each", "on_error"), default="never"
                ),
                "reset_kind": _string(
                    "raw reset or reset plus retained access control.", enum=("raw", "reauth"), default="raw"
                ),
                "include_state_changing": _boolean("Allow generated INS values such as VERIFY/UPDATE/ERASE.", False),
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
