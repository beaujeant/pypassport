from types import SimpleNamespace

import pytest

from pypassport.doc9303 import converter
from pypassport.doc9303.data_group import DataGroupDump


def test_converter_uses_canonical_protocol_identifiers():
    assert converter.to_dg("61") == "DG1"
    assert converter.to_ef("DG1") == "EF.DG1"
    assert converter.to_fid("EF.DG1") == "0101"
    assert converter.to_tag("0101") == "61"
    assert converter.to_class("DG1") == "DataGroup1"
    assert converter.to_other("DG1") == "1"


def test_converter_rejects_removed_golden_reader_dump_names():
    with pytest.raises(KeyError):
        converter.to_dg("Datagroup1")


def test_data_group_dump_uses_canonical_names(tmp_path):
    dump = DataGroupDump(tmp_path, ".bin")

    dump.dump_dg(SimpleNamespace(tag="61", file=b"dg1"))
    dump.dump_dg(SimpleNamespace(tag="ATR/INFO", file=b"atr"))

    assert (tmp_path / "DG1.bin").read_bytes() == b"dg1"
    assert (tmp_path / "ATR_INFO.bin").read_bytes() == b"atr"
