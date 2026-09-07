"""Direct MCP stdio streams for reliable operation on PC/SC workstations."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import anyio
from anyio.abc import ObjectReceiveStream, ObjectSendStream
from mcp import types
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage


class _ReceiveStream(ObjectReceiveStream[SessionMessage | Exception]):
    def __init__(self, reader: asyncio.StreamReader, transport: asyncio.BaseTransport):
        self.reader = reader
        self.transport = transport

    async def receive(self) -> SessionMessage | Exception:
        line = await self.reader.readline()
        if not line:
            raise anyio.EndOfStream
        try:
            message = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
        except Exception as exc:
            return exc
        return SessionMessage(message)

    async def aclose(self) -> None:
        self.transport.close()


class _SendStream(ObjectSendStream[SessionMessage]):
    async def send(self, item: SessionMessage) -> None:
        data = (item.message.model_dump_json(by_alias=True, exclude_unset=True) + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(1, view)
            view = view[written:]

    async def aclose(self) -> None:
        return None


async def run_stdio(server: Any) -> None:
    """Run an MCPServer over NDJSON stdin/stdout without worker-thread I/O.

    The high-level SDK's stdio bridge performs file reads in AnyIO workers.
    PC/SC hosts and application sandboxes sometimes restrict that worker path;
    direct asyncio pipe reads avoid the compatibility failure while the SDK's
    low-level Server continues to own all JSON-RPC/MCP handling. On Windows,
    Python 3.10's Proactor loop can reject a subprocess standard-input pipe
    passed to ``connect_read_pipe``. The SDK's stdio transport handles that
    platform-specific pipe setup, so use it there.
    """

    if sys.platform == "win32":
        async with stdio_server() as (receive, send):
            await server._lowlevel_server.run(  # MCPServer exposes no public custom-stream runner in v2.
                receive,
                send,
                server._lowlevel_server.create_initialization_options(),
            )
        return

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    receive = _ReceiveStream(reader, transport)
    send = _SendStream()
    await server._lowlevel_server.run(  # MCPServer exposes no public custom-stream runner in v2.
        receive,
        send,
        server._lowlevel_server.create_initialization_options(),
    )
