"""Tests for the optional PC/SC reader boundary."""

from __future__ import annotations

import subprocess
import sys
import textwrap

from pypassport import reader


class _Reader:
    def __init__(self, name):
        self.name = name
        self.connections = 0

    def __str__(self):
        return self.name

    def createConnection(self):
        self.connections += 1
        return f"connection:{self.name}"


def test_explicit_unknown_reader_does_not_fall_back_to_first(monkeypatch):
    first = _Reader("first")
    second = _Reader("second")
    monkeypatch.setattr(reader, "list_readers", lambda: [first, second])

    assert reader.get_reader("missing") is None
    assert first.connections == 0
    assert second.connections == 0


def test_core_import_and_hex_helpers_work_without_pyscard():
    script = textwrap.dedent(
        """
        import builtins

        real_import = builtins.__import__

        def blocked_import(name, *args, **kwargs):
            if name == "smartcard" or name.startswith("smartcard."):
                raise ImportError("smartcard intentionally blocked")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = blocked_import

        import pypassport
        from pypassport import reader
        from pypassport.utils import to_hex_string

        assert to_hex_string(b"ABC") == "414243"
        try:
            reader.list_readers()
        except reader.ReaderException as exc:
            assert "pypassport[reader]" in str(exc)
        else:
            raise AssertionError("reader.list_readers() should require the reader extra")
        """
    )

    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
