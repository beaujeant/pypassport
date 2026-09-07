import asyncio
import os
import sys
from contextlib import asynccontextmanager

from mcp import Client, StdioServerParameters

from epassportmcp import stdio
from epassportmcp.bridge import ViewerMCPHost
from epassportmcp.server import mcp


def test_mcp_advertises_only_three_lazy_front_door_tools():
    async def inspect_server():
        async with Client(mcp, read_timeout_seconds=10) as client:
            result = await client.list_tools()
            return {tool.name: tool.input_schema for tool in result.tools}

    tools = asyncio.run(inspect_server())

    assert set(tools) == {"epassport_list_tools", "epassport_recommend_tools", "epassport_call"}
    assert "action" in tools["epassport_call"]["properties"]
    assert "enum" not in tools["epassport_call"]["properties"]["action"]


def test_stdio_uses_sdk_transport_on_windows(monkeypatch):
    receive = object()
    send = object()
    options = object()
    calls = []

    @asynccontextmanager
    async def fake_stdio_server():
        yield receive, send

    class LowLevelServer:
        def create_initialization_options(self):
            return options

        async def run(self, actual_receive, actual_send, actual_options):
            calls.append((actual_receive, actual_send, actual_options))

    class Server:
        _lowlevel_server = LowLevelServer()

    monkeypatch.setattr(stdio.sys, "platform", "win32")
    monkeypatch.setattr(stdio, "stdio_server", fake_stdio_server)

    asyncio.run(stdio.run_stdio(Server()))

    assert calls == [(receive, send, options)]


def test_stdio_entrypoint_serves_lazy_catalog_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setenv("EPASSPORT_VIEWER_SOCKET", str(tmp_path / "viewer.sock"))

    class Viewer:
        reader = None
        iso7816 = None
        ep = None
        _reader_name = ""
        _mcp_mrz = None
        _mcp_can = None

    host = ViewerMCPHost(Viewer())
    host.start()

    async def inspect_server():
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "epassportmcp"],
            env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
        )
        async with Client(parameters, read_timeout_seconds=10) as client:
            tools = await client.list_tools()
            catalog = await client.call_tool("epassport_list_tools", {"group": "transport"})
            executed = await client.call_tool(
                "epassport_call",
                {
                    "action": "attack.aa_compare",
                    "arguments": {"modulus_hex": "A1B2", "highest_signature_hex": "90FF"},
                },
            )
            return tools, catalog, executed

    try:
        tools, catalog, executed = asyncio.run(inspect_server())
    finally:
        host.stop()

    assert {tool.name for tool in tools.tools} == {
        "epassport_list_tools",
        "epassport_recommend_tools",
        "epassport_call",
    }
    assert catalog.is_error is False
    assert [action["name"] for action in catalog.structured_content["actions"]] == [
        "apdu.transmit",
        "apdu.history",
        "apdu.clear_history",
    ]
    assert executed.is_error is False
    assert executed.structured_content["result"]["may_belong_to_same_passport"] is True
