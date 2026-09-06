from pypassport.apdu_history import APDUHistory
from pypassport.iso7816 import ISO7816, APDUCommand, APDUResponse


class _Connection:
    def __init__(self):
        self.requests = []

    def transmit(self, command):
        self.requests.append(command)
        return [0xCA, 0xFE], 0x6A, 0x82


def test_transmit_raw_preserves_short_or_malformed_wire_bytes():
    APDUHistory.get().clear()
    connection = _Connection()
    iso = ISO7816(connection)

    response = iso.transmit_raw("00:A4 03")

    assert connection.requests == [[0x00, 0xA4, 0x03]]
    assert response.raw() == bytes.fromhex("CAFE6A82")
    tx = APDUHistory.get()[-1]
    assert tx.wire_request_hex == "00A403"
    assert tx.wire_response_hex == "CAFE6A82"


def test_attack_pair_helpers_build_one_external_authenticate_apdu(monkeypatch):
    from pypassport.attacks.brute_force import BruteForce
    from pypassport.attacks.mac_traceability import MacTraceability

    iso = ISO7816(_Connection())
    monkeypatch.setattr(iso, "rst_connection", lambda: None)
    monkeypatch.setattr(iso, "get_challenge", lambda: b"12345678")
    calls = []

    def transmit(command, *_args, **_kwargs):
        calls.append(command)
        return APDUResponse([], 0x69, 0x82) if _kwargs.get("full") else b""

    monkeypatch.setattr(iso, "transmit", transmit)

    MacTraceability(iso)._send_pair()
    BruteForce(iso)._send_cmd_data(bytes(40))

    assert len(calls) == 2
    assert all(isinstance(command, APDUCommand) and command.ins == "82" for command in calls)
