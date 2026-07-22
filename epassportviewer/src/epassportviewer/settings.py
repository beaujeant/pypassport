"""Persistent application settings — a thin JSON store in the app data dir.

Only a handful of preferences need to survive across runs (currently the CSCA
certificate directory used for Passive Authentication), so this is deliberately
minimal: a dict backed by a JSON file that is rewritten whenever a value
changes. A missing or corrupt file simply starts from empty defaults.
"""

import json
import logging


class Settings:
    def __init__(self, path):
        """@param path: Path to the JSON settings file (created on first save)."""
        self._path = path
        self._data = {}
        self.load()

    def load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            self._data = {}
            return
        except (OSError, json.JSONDecodeError) as e:
            logging.warning("Could not read settings (%s); using defaults.", e)
            self._data = {}
            return
        self._data = data if isinstance(data, dict) else {}

    def save(self):
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except OSError as e:
            logging.error("Could not write settings: %s", e)

    @property
    def csca_dir(self):
        """Directory of trusted CSCA certificates for Passive Authentication."""
        return self._data.get("csca_dir", "")

    @csca_dir.setter
    def csca_dir(self, value):
        self._data["csca_dir"] = (value or "").strip()
        self.save()
