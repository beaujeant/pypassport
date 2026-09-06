import asyncio
import sys

from mcp import Client, StdioServerParameters

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


def test_stdio_entrypoint_serves_lazy_catalog_end_to_end():
    async def inspect_server():
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "epassportmcp"])
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

    tools, catalog, executed = asyncio.run(inspect_server())

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
