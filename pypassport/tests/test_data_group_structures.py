import json

from pypassport.doc9303.data_group import CVCA, DataGroup2, DataGroup11, DataGroup16


def _length(value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _tlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + _length(value) + value


def _face_block(image: bytes) -> bytes:
    image_info = (
        b"\x02"  # Full front
        b"\x01"  # JPEG 2000
        b"\x00\x64"  # width
        b"\x00\x78"  # height
        b"\x01"  # RGB24
        b"\x02"  # static digital
        b"\x00\x01"  # device type
        b"\x00\x00"  # unspecified quality
    )
    fixed = (
        b"\x00\x00"  # number of feature points
        b"\x00"  # gender
        b"\x00"  # eye colour
        b"\x00"  # hair colour
        b"\x00\x00\x00"  # feature mask
        b"\x00\x00"  # expression
        b"\x00\x00\x00"  # pose angle
        b"\x00\x00\x00"  # pose uncertainty
    )
    block_length = 4 + len(fixed) + len(image_info) + len(image)
    return block_length.to_bytes(4, "big") + fixed + image_info + image


def _fac_record(*images: bytes) -> bytes:
    blocks = b"".join(_face_block(image) for image in images)
    record_length = 14 + len(blocks)
    return b"FAC\x00" + b"010\x00" + record_length.to_bytes(4, "big") + len(images).to_bytes(2, "big") + blocks


def test_ef_cvca_retains_current_reference_without_cardaccess_parser_confusion():
    ef = CVCA(file=_tlv("42", b"BENCVCA00005"))

    assert ef["current_reference"] == "BENCVCA00005"


def test_dg2_parses_all_fac_images_and_renders_json():
    bht = _tlv("87", b"\x01\x01") + _tlv("88", b"\x00\x08")
    fac = _fac_record(b"first-image", b"second-image")
    bit = _tlv("A1", bht) + _tlv("5F2E", fac)
    dg = DataGroup2(file=_tlv("75", _tlv("7F61", _tlv("02", b"\x01") + _tlv("7F60", bit))))

    assert dg.get_biometric_data() == [b"first-image", b"second-image"]
    metadata = dg["7F61"][0]["7F60"]["meta"]
    assert metadata["NumberOfFacialImages"] == 2
    assert metadata["FacialImages"][0]["ImageDataType"] == "JPEG 2000"
    assert metadata["FacialImages"][1]["ImageLength"] == len(b"second-image")
    assert dg["7F61"][0]["7F60"]["5F2E"] == fac
    assert dg["7F61"][0]["7F60"]["primary_image"] == b"first-image"

    rendered = json.loads(dg.to_json())
    assert rendered["name"] == "DG2"
    assert rendered["raw_body_hex"] == dg.body.hex().upper()
    assert rendered["data"]["7F61"][0]["7F60"]["5F2E"] == fac.hex().upper()
    assert rendered["data"]["7F61"][0]["7F60"]["meta"]["FacialImages"][0]["ImageData"] == b"first-image".hex().upper()


def test_dg2_keeps_partial_content_when_counted_template_mismatches():
    bht = _tlv("87", b"\x01\x01") + _tlv("88", b"\x00\x08")
    bit = _tlv("A1", bht) + _tlv("5F2E", _fac_record(b"face"))
    body = _tlv("7F61", _tlv("02", b"\x02") + _tlv("7F60", bit))
    dg = DataGroup2(file=_tlv("75", body))

    assert len(dg["7F61"]) == 1
    assert dg.get_biometric_data() == [b"face"]
    assert dg["raw"] == dg.body
    assert any("declared 2 7F60 templates" in error["message"] for error in dg["parse_errors"])


def test_dg2_keeps_bare_bdb_visible_when_bht_is_missing():
    fac = _fac_record(b"face")
    body = _tlv("7F61", _tlv("02", b"\x01") + _tlv("7F60", _tlv("5F2E", fac)))
    dg = DataGroup2(file=_tlv("75", body))

    assert dg["7F61"][0]["7F60"]["5F2E"] == fac
    assert dg.get_biometric_data() == [b"face"]
    assert any("missing A1 BHT" in error["message"] for error in dg["parse_errors"])


def test_dg11_parses_other_names_from_a0_only():
    other_names = _tlv("02", b"\x02") + _tlv("5F0F", b"ALICE") + _tlv("5F0F", b"BOB")
    body = _tlv("5C", bytes.fromhex("A05F17")) + _tlv("A0", other_names) + _tlv("5F17", b"X123<Y456")
    dg = DataGroup11(file=_tlv("6B", body))

    assert dg["A0"]["02"] == 2
    assert dg["A0"]["5F0F"] == [b"ALICE", b"BOB"]
    assert dg["5F17"] == b"X123<Y456"
    readable = json.loads(dg.to_readable_json())
    assert readable["data"]["Context specific constructed data objects [A0]"]["Count [02]"] == 2
    assert readable["data"]["Context specific constructed data objects [A0]"]["Other names [5F0F]"] == ["ALICE", "BOB"]


def test_dg11_renders_tagged_readable_json_alongside_raw_json():
    body = (
        _tlv("5C", bytes.fromhex("5F0E5F2B5F11"))
        + _tlv("5F0E", b"DOE<<JANE<ALICE<G.")
        + _tlv("5F2B", b"20000101")
        + _tlv("5F11", b"TESTVILLE")
    )
    dg = DataGroup11(file=_tlv("6B", body))

    raw = json.loads(dg.to_json())
    readable = json.loads(dg.to_readable_json())

    assert raw["data"]["5F0E"] == "444F453C3C4A414E453C414C4943453C472E"
    assert readable["outer_tag"] == "Template for Additional Personal Details [6B]"
    assert readable["data"]["Tag list [5C]"] == [
        "Full name, in national characters [5F0E]",
        "Date of birth [5F2B]",
        "Place of birth [5F11]",
    ]
    assert readable["data"]["Full name, in national characters [5F0E]"] == "DOE, JANE ALICE G."
    assert readable["data"]["Date of birth [5F2B]"] == "2000-01-01"
    assert readable["data"]["Place of birth [5F11]"] == "TESTVILLE"


def test_dg16_parses_current_ax_template_layout():
    person1 = _tlv("5F50", b"20260101") + _tlv("5F51", b"ALICE") + _tlv("5F52", b"+320000") + _tlv("5F53", b"BRUSSELS")
    person2 = _tlv("5F50", b"20260102") + _tlv("5F51", b"BOB") + _tlv("5F52", b"+321111") + _tlv("5F53", b"ANTWERP")
    dg = DataGroup16(file=_tlv("70", _tlv("02", b"\x02") + _tlv("A1", person1) + _tlv("A2", person2)))

    assert dg["number_of_templates"] == 2
    assert dg["persons"][0]["template_tag"] == "A1"
    assert dg["persons"][0]["5F51"] == b"ALICE"
    assert dg["persons"][1]["template_tag"] == "A2"
    assert dg["persons"][1]["5F53"] == b"ANTWERP"


def test_dg16_keeps_raw_when_count_does_not_match_templates():
    person = _tlv("5F50", b"20260101") + _tlv("5F51", b"ALICE")
    dg = DataGroup16(file=_tlv("70", _tlv("02", b"\x02") + _tlv("A1", person)))

    assert dg["persons"][0]["5F51"] == b"ALICE"
    assert dg["raw"] == dg.body
    assert any("declared 2 person templates" in error["message"] for error in dg["parse_errors"])
