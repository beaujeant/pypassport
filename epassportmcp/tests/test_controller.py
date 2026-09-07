from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from epassportmcp import bridge
from epassportmcp.bridge import ViewerMCPClient, ViewerMCPHost, ViewerUnavailable, _capability_path
from epassportmcp.controller import ActionError, PassportController
from pypassport import reader
from pypassport.apdu_history import APDUHistory
from pypassport.doc9303.access_control import NegotiationResult
from pypassport.doc9303.file_system import FileProbe
from pypassport.iso7816 import ISO7816


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
        assert error.details == {"install": "epassportviewer"}
    else:
        raise AssertionError("missing PC/SC support was not surfaced")


def test_advanced_protocol_and_filesystem_actions_are_first_class(tmp_path):
    controller = PassportController()
    controller.iso7816 = SimpleNamespace(ciphering=object(), reader_connection=None)

    class FakePassport(dict):
        def __init__(self):
            super().__init__()
            self.access_control = SimpleNamespace(mechanism="PACE", downgraded=False, pace_info=None)
            self.file_system = SimpleNamespace(
                applications=lambda: ["A0000002471001"],
                enumerate=lambda application, extra_fids=(): [
                    FileProbe(application, extra_fids[0], None, None, True, b"", "9000")
                ],
            )
            self.files = {
                name: SimpleNamespace(file=name.encode(), get=lambda _name, default=(): default)
                for name in ("COM", "DG1", "SOD")
            }

        def __getitem__(self, name):
            return self.files[name]

        def do_verify_dg_integrity(self, _files):
            return {"DG1": True}

        def do_chip_authentication(self, **kwargs):
            return {"version": 2, "key_size": 256, **kwargs}

        def do_terminal_authentication(self, chain, key, id_picc, **kwargs):
            return {
                "rights": {"read_dg3": False},
                "negative_rights": [],
                "input_lengths": [len(chain), len(key), len(id_picc)],
            }

    controller.passport = FakePassport()
    filesystem = controller.execute("passport.filesystem", {"extra_fids": ["01FE"]})["result"]
    assert filesystem["enumerated"][0]["files"][0]["fid"] == "01FE"
    ca = controller.execute("security.chip_authentication", {"source": "DG14", "key_id": 7})["result"]
    assert ca["version"] == 2 and ca["key_id"] == 7

    cvc = tmp_path / "terminal.cvc"
    key = tmp_path / "terminal.der"
    anchor = tmp_path / "cvca.cvc"
    for path in (cvc, key, anchor):
        path.write_bytes(b"credential")
    ta = controller.execute("security.terminal_authentication", {
        "terminal_chain_paths": [str(cvc)],
        "private_key_path": str(key),
        "trust_anchor_paths": [str(anchor)],
        "id_picc_hex": "0102",
    })["result"]
    assert ta["input_lengths"] == [1, 10, 2]


def test_bounded_discovery_and_access_matrix_preserve_probe_status(monkeypatch):
    APDUHistory.get().clear()
    connection = FakeConnection()
    monkeypatch.setattr(reader, "get_reader", lambda _selector=None: connection)
    controller = PassportController()
    controller.execute("session.connect")

    discovery = controller.execute(
        "security.discover_files",
        {"application": "A0000002471001", "fid_start": "01F0", "fid_end": "01F1", "max_probes": 2},
    )["result"]
    assert discovery["probe_count"] == 2
    assert discovery["status_histogram"] == {"9000": 2}

    matrix = controller.execute(
        "security.access_matrix",
        {"states": ["none"], "files": ["DG1"], "paths": ["fid", "sfi"], "max_probes": 2},
    )["result"]
    assert matrix["outcomes"] == {"pass": 2}
    assert {cell["phase"] for cell in matrix["cells"]} == {"read"}


def test_fuzz_safety_profile_rejects_opaque_wire_campaign(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(reader, "get_reader", lambda _selector=None: connection)
    controller = PassportController()
    controller.execute("session.connect")

    try:
        controller.execute(
            "fuzz.run",
            {"seed_apdu_hex": "00A4020C020101", "channel": "wire", "reset_policy": "before_each"},
        )
    except ActionError as error:
        assert error.code == "unsafe_wire_fuzz"
    else:
        raise AssertionError("opaque wire campaign was accepted under read_only")


def test_bridge_executes_in_viewer_process_and_uses_in_memory_traffic(monkeypatch, tmp_path):
    monkeypatch.setenv("EPASSPORT_VIEWER_SOCKET", str(tmp_path / "viewer.sock"))
    APDUHistory.get().clear()
    connection = FakeConnection()
    connection.connect()

    class Viewer:
        reader = connection
        iso7816 = ISO7816(connection)
        ep = None
        _reader_name = "Research reader"
        _mcp_mrz = None
        _mcp_can = None

    host = ViewerMCPHost(Viewer())
    host.start()
    try:
        result = ViewerMCPClient().request(
            "action", {"action": "apdu.transmit", "arguments": {"apdu_hex": "00010000", "channel": "current"}}
        )
    finally:
        host.stop()

    assert result["result"]["status_word"] == "9000"
    assert len(APDUHistory.get()) == 1
    assert APDUHistory.get()[0].source == "mcp-current"


def test_bridge_requires_viewer_approval_for_arbitrary_apdus(monkeypatch, tmp_path):
    monkeypatch.setenv("EPASSPORT_VIEWER_SOCKET", str(tmp_path / "viewer.sock"))
    class Viewer:
        reader = None
        iso7816 = None
        ep = None
        _reader_name = ""
        _mcp_mrz = None
        _mcp_can = None

        def approve_mcp_action(self, action, effect):
            return False

    host = ViewerMCPHost(Viewer())
    host.start()
    try:
        result = ViewerMCPClient().request(
            "action", {"action": "apdu.transmit", "arguments": {"apdu_hex": "00010000", "channel": "current"}}
        )
    finally:
        host.stop()

    assert result["error"]["code"] == "viewer_denied"


def test_bridge_capability_is_ephemeral_and_private(monkeypatch, tmp_path):
    address = tmp_path / "viewer.sock"
    monkeypatch.setenv("EPASSPORT_VIEWER_SOCKET", str(address))

    class Viewer:
        reader = None
        iso7816 = None
        ep = None
        _reader_name = ""
        _mcp_mrz = None
        _mcp_can = None

    authkey = b"\n" + (b"x" * 31)
    host = ViewerMCPHost(Viewer())
    with monkeypatch.context() as context:
        context.setattr(bridge.os, "urandom", lambda size: authkey)
        host.start()
    capability = _capability_path(str(address))
    try:
        assert address.exists()
        assert capability.read_bytes() == authkey
        # NTFS permissions are represented by an ACL, while ``st_mode`` on
        # Windows reports compatibility bits and cannot express 0o600.
        if sys.platform != "win32":
            assert capability.stat().st_mode & 0o777 == 0o600
    finally:
        host.stop()

    assert not address.exists()
    assert not capability.exists()

    host.start()
    try:
        assert ViewerMCPClient().request("list")["groups"]
    finally:
        host.stop()


def test_default_unix_endpoint_does_not_depend_on_xdg_runtime_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("EPASSPORT_VIEWER_SOCKET", raising=False)
    without_xdg = bridge.endpoint()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "gui-runtime"))

    assert bridge.endpoint() == without_xdg


def test_second_host_does_not_disable_existing_host(monkeypatch, tmp_path):
    monkeypatch.setenv("EPASSPORT_VIEWER_SOCKET", str(tmp_path / "viewer.sock"))

    class Viewer:
        reader = None
        iso7816 = None
        ep = None
        _reader_name = ""
        _mcp_mrz = None
        _mcp_can = None

    first = ViewerMCPHost(Viewer())
    second = ViewerMCPHost(Viewer())
    first.start()
    try:
        with pytest.raises(ViewerUnavailable, match="already owns"):
            second.start()
        assert _capability_path(str(tmp_path / "viewer.sock")).exists()
        assert ViewerMCPClient().request("list")["groups"]
    finally:
        first.stop()


def test_bridge_has_no_headless_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("EPASSPORT_VIEWER_SOCKET", str(tmp_path / "absent.sock"))

    with pytest.raises(ViewerUnavailable, match="not enabled"):
        ViewerMCPClient().request("list")


def test_windows_bridge_uses_a_per_user_named_pipe(monkeypatch):
    monkeypatch.setattr(bridge.sys, "platform", "win32")
    monkeypatch.setattr(bridge.getpass, "getuser", lambda: "DOMAIN\\researcher")

    address, family = bridge.endpoint()

    assert family == "AF_PIPE"
    assert address == r"\\.\pipe\epassportviewer-mcp-DOMAIN_researcher"

    transport, transport_family = bridge._transport_endpoint(address, family)
    assert transport_family == "AF_INET"
    assert transport[0] == "127.0.0.1"
    assert 49152 <= transport[1] <= 65535


def test_conformance_action_does_not_return_passport_content():
    controller = PassportController()
    controller.iso7816 = SimpleNamespace(ciphering=None, reader_connection=None)

    class FakePassport(dict):
        access_control = SimpleNamespace(mechanism="PACE", downgraded=False, pace_info=None)
        file_system = SimpleNamespace(enumerate=lambda *_args, **_kwargs: [])

        def __getitem__(self, name):
            return SimpleNamespace(file=("PERSONAL-" + name).encode(), get=lambda _name, default=(): default)

        def do_verify_dg_integrity(self, _files):
            return {"DG1": True}

    controller.passport = FakePassport()
    result = controller.execute("security.conformance", {})["result"]
    assert result["verdict"] == "PASS"
    assert "PERSONAL" not in str(result)
