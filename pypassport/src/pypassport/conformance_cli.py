"""Headless live interoperability runner used by laboratories and CI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pypassport import reader
from pypassport.conformance import ConformanceProfile, ConformanceRunner
from pypassport.epassport import EPassport


def _profile(path: str | None) -> ConformanceProfile:
    if not path:
        return ConformanceProfile()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("The conformance profile must be a JSON object")
    return ConformanceProfile.from_mapping(payload)


def _credentials() -> tuple[object | None, str | None]:
    mrz = os.environ.get("EPASSPORT_MRZ", "").strip()
    can = os.environ.get("EPASSPORT_CAN", "").strip() or None
    if mrz:
        return mrz, can
    fields = tuple(os.environ.get(name, "").strip() for name in (
        "EPASSPORT_DOCUMENT_NUMBER", "EPASSPORT_DATE_OF_BIRTH", "EPASSPORT_DATE_OF_EXPIRY"
    ))
    return (fields if all(fields) else None), can


def _terminal_credentials(profile: ConformanceProfile) -> dict[str, object] | None:
    if not profile.verify_terminal_authentication:
        return None
    chain_paths = [value for value in os.environ.get("EPASSPORT_TA_CHAIN", "").split(os.pathsep) if value]
    anchor_paths = [value for value in os.environ.get("EPASSPORT_CVCA_ANCHORS", "").split(os.pathsep) if value]
    key_path = os.environ.get("EPASSPORT_TA_PRIVATE_KEY", "")
    id_picc = bytes.fromhex(os.environ.get("EPASSPORT_ID_PICC", ""))
    if not chain_paths or not anchor_paths or not key_path or not id_picc:
        raise ValueError(
            "TA profiles require EPASSPORT_TA_CHAIN, EPASSPORT_CVCA_ANCHORS, "
            "EPASSPORT_TA_PRIVATE_KEY, and EPASSPORT_ID_PICC"
        )
    return {
        "terminal_chain": [Path(path).read_bytes() for path in chain_paths],
        "private_key_der": Path(key_path).read_bytes(),
        "id_picc": id_picc,
        "trust_anchors": [Path(path).read_bytes() for path in anchor_paths],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", help="Exact PC/SC reader name (default: first reader)")
    parser.add_argument("--access-control", choices=("auto", "pace", "bac", "none"), default="auto")
    parser.add_argument("--allow-bac-fallback", action="store_true")
    parser.add_argument("--profile", help="JSON file containing non-secret issuer/lab expectations")
    parser.add_argument("--csca-directory", help="Trusted CSCA/Master List directory")
    parser.add_argument("--report", help="Write the redacted result to this path instead of stdout")
    args = parser.parse_args(argv)
    mrz, can = _credentials()
    if args.access_control != "none" and mrz is None and can is None:
        parser.error(
            "Set EPASSPORT_MRZ or EPASSPORT_DOCUMENT_NUMBER/DATE_OF_BIRTH/DATE_OF_EXPIRY, "
            "or EPASSPORT_CAN in the environment"
        )
    connection = reader.get_reader(args.reader)
    if connection is None:
        print("No matching PC/SC reader found", file=sys.stderr)
        return 3
    passport = EPassport(connection, mrz, select_aid=False)
    passport.open(
        access_control=args.access_control,
        can=can,
        allow_bac_fallback=args.allow_bac_fallback,
    )
    profile = _profile(args.profile)
    report = ConformanceRunner(passport).run(
        profile,
        csca_directory=args.csca_directory,
        terminal_credentials=_terminal_credentials(profile),
    ).to_dict()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        Path(args.report).write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0 if report["verdict"] == "PASS" else 2


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
