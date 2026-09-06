from __future__ import annotations

from pypassport import reader
from pypassport.apdu_history import APDUHistory
from pypassport.doc9303.access_control import NegotiationResult

from epassportmcp.controller import ActionError, PassportController


class FakeConnection:
    def __init__(self):
        self.transmitted: list[list[int]] = []
        self.connected = 0
        self.disconnected = 0

    def connect(self):
        self.connected += 1

    def disconnect(self):
        self.disconnected += 1

    def getReader(self):
        return "Research reader"

    def getATR(self):
        return [0x3B, 0x00]

    def transmit(self, command):
        self.transmitted.append(list(command))
        if list(command) == [0x01, 0x02, 0x03]:
            return [0xAA], 0x6A, 0x82
        return [], 0x90, 0x00


def test_low_level_session_attach_and_exact_wire_transport(monkeypatch):
    APDUHistory.get().clear()
    connection = FakeConnection()
    monkeypatch.setattr(reader, "get_reader", lambda _selector=None: connection)

    controller = PassportController()
    connected = controller.execute("session.connect", {})
    assert connected["result"]["atr_hex"] == "3B00"

    authenticated = controller.execute("session.authenticate", {"access_control": "none", "reset_before": False})
    assert authenticated["result"]["mechanism"] == "NONE"
    assert controller.passport is not None
    assert controller.passport.iso7816 is controller.iso7816

    result = controller.execute("apdu.transmit", {"apdu_hex": "01:02 03", "channel": "wire"})["result"]
    assert result["status_word"] == "6A82"
    assert result["wire_request_hex"] == "010203"
    assert result["wire_response_hex"] == "AA6A82"
    assert connection.transmitted[-1] == [0x01, 0x02, 0x03]
    assert controller.execute("session.status")["result"]["access_control"] == "none"


def test_raw_reset_and_reauthentication_reuse_credentials_and_transport(monkeypatch):
    APDUHistory.get().clear()
    connection = FakeConnection()
    monkeypatch.setattr(reader, "get_reader", lambda _selector=None: connection)

    class DummyCipher:
        pass

    opens: list[tuple[str, str | None]] = []

    def fake_open(self, mrz=None, access_control="auto", can=None):
        opens.append((access_control, can))
        self.iso7816.ciphering = DummyCipher()
        self._access_control = NegotiationResult(access_control.upper())
        return self._access_control

    monkeypatch.setattr("pypassport.epassport.EPassport.open", fake_open)

    controller = PassportController()
    controller.execute("session.connect")
    controller.execute(
        "session.authenticate",
        {"mrz": ["123456789", "740812", "120415"], "access_control": "bac", "reset_before": True},
    )
    original_iso = controller.iso7816
    assert original_iso is not None and original_iso.ciphering is not None

    reset = controller.execute("session.reset", {"kind": "reauth"})
    assert controller.iso7816 is original_iso
    assert reset["session"]["secure_messaging"] == "3DES"
    assert opens == [("bac", None), ("bac", None)]


def test_catalog_and_recommendation_only_expand_selected_schemas():
    controller = PassportController()
    default = controller.list_actions()
    assert "actions" not in default
    assert default["total_actions"] >= 20

    transport = controller.list_actions(group="transport")
    assert transport["actions"]
    assert all("input_schema" not in action for action in transport["actions"])

    detailed = controller.list_actions(query="apdu.transmit", detail=True)
    assert detailed["actions"][0]["input_schema"]["required"] == ["apdu_hex"]

    recipe = controller.recommend("send malformed raw APDU and restart encrypted communication")
    names = [step["action"] for step in recipe["workflow"]]
    assert "apdu.transmit" in names
    assert "session.reset" in names
    assert len(recipe["actions"]) == len(names)


def test_built_in_schema_validation_covers_catalog_inputs():
    controller = PassportController()

    for arguments in (
        {},
        {"apdu_hex": "00A4", "extra": True},
        {"apdu_hex": "00A4", "channel": "invalid"},
    ):
        try:
            controller.execute("apdu.transmit", arguments)
        except ActionError as error:
            assert error.code == "invalid_arguments"
        else:
            raise AssertionError("invalid APDU arguments were accepted")

    try:
        controller.execute("session.authenticate", {"mrz": ["one", "two"]})
    except ActionError as error:
        assert error.code == "invalid_arguments"
    else:
        raise AssertionError("invalid oneOf/array bounds were accepted")

    try:
        controller.execute("fuzz.run", {"seed_apdu_hex": "00A4", "repeat_each": True})
    except ActionError as error:
        assert error.code == "invalid_arguments"
    else:
        raise AssertionError("boolean was accepted as an integer")


def test_missing_pcsc_is_an_actionable_optional_dependency_error(monkeypatch):
    monkeypatch.setattr(
        reader,
        "list_readers",
        lambda: (_ for _ in ()).throw(reader.ReaderException("PC/SC support is unavailable")),
    )

    try:
        PassportController().execute("reader.list")
    except ActionError as error:
        assert error.code == "pcsc_unavailable"
        assert error.details == {"install": "epassportviewer-mcp[reader]"}
    else:
        raise AssertionError("missing PC/SC support was not surfaced")
