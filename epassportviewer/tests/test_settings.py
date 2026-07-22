"""Tests for the persistent settings store.

These exercise the pure JSON-backed logic only; no Tk widgets are built, so the
tests run headless (importing ``epassportviewer.settings`` does not pull in
tkinter).
"""

import json

import pytest

from epassportviewer.settings import Settings


def test_defaults_when_file_missing(tmp_path):
    s = Settings(tmp_path / "settings.json")
    assert s.csca_dir == ""
    # Reading a default must not create the file.
    assert not (tmp_path / "settings.json").exists()


def test_set_persists_and_strips(tmp_path):
    path = tmp_path / "settings.json"
    s = Settings(path)
    s.csca_dir = "  /certs/csca  "
    assert s.csca_dir == "/certs/csca"  # whitespace trimmed
    assert json.loads(path.read_text()) == {"csca_dir": "/certs/csca"}
    # A fresh instance reads the same value back.
    assert Settings(path).csca_dir == "/certs/csca"


def test_clearing_value(tmp_path):
    path = tmp_path / "settings.json"
    s = Settings(path)
    s.csca_dir = "/certs/csca"
    s.csca_dir = ""
    assert s.csca_dir == ""
    assert Settings(path).csca_dir == ""


@pytest.mark.parametrize("garbage", ["{ not json", "", "[1, 2, 3]", "42"])
def test_corrupt_or_unexpected_file_falls_back_to_defaults(tmp_path, garbage):
    path = tmp_path / "settings.json"
    path.write_text(garbage)
    # A malformed or non-object file must not raise, just start fresh.
    assert Settings(path).csca_dir == ""
