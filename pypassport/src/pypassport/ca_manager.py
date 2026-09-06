"""Trusted CSCA certificate store management."""

from __future__ import annotations

import logging
from pathlib import Path

from pypassport.doc9303 import cms


class CAManagerException(Exception):
    pass


class CAManager:
    """Load trusted CSCA certificates or ICAO Master Lists from one directory."""

    _CERT_EXTENSIONS = (".cer", ".crt", ".pem", ".der", ".ml")

    def __init__(self, directory: str | Path, *, master_list_signers=None, allow_unverified_master_lists=False):
        self._dir = Path(directory).expanduser()
        self._master_list_signers = tuple(master_list_signers or ())
        self._allow_unverified_master_lists = allow_unverified_master_lists
        self._cache = None

    def get_certificates(self) -> list[bytes]:
        """Load all valid X.509 certificates in the configured directory."""

        if not self._dir.is_dir():
            raise CAManagerException(f"{self._dir} is not a valid CSCA certificate directory")

        if self._cache is not None:
            return list(self._cache)
        certs: list[bytes] = []
        for path in sorted(self._dir.iterdir()):
            if not path.is_file() or path.suffix.lower() not in self._CERT_EXTENSIONS:
                continue
            try:
                data = path.read_bytes()
                loaded = (cms.load_master_list_certificates(
                    data,
                    self._master_list_signers,
                    allow_unverified=self._allow_unverified_master_lists,
                ) if path.suffix.lower() == ".ml" else cms.load_certificates(data))
            except Exception as exc:
                logging.warning("CAManager: could not read %s (%s)", path.name, exc)
                continue
            valid = [der for der in loaded if cms.is_certificate(der)]
            if not valid:
                logging.warning("CAManager: %s contains no valid certificate - skipping", path.name)
            certs.extend(valid)

        if not certs:
            raise CAManagerException(f"No CSCA certificate has been found in {self._dir}")
        # Master Lists can contain duplicate rollover/link entries. Stable
        # deduplication materially reduces path-building work on large PKDs.
        self._cache = tuple(dict.fromkeys(certs))
        return list(self._cache)

    @property
    def dir(self) -> str:
        """Return the configured certificate directory as a string."""

        return str(self._dir)
