"""Model Context Protocol stdio server for AI-assisted ePassport research."""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .bridge import ViewerMCPClient, ViewerUnavailable
from .stdio import run_stdio

bridge = ViewerMCPClient()
mcp = MCPServer(
    "ePassportViewer",
    instructions=(
        "Bridge to a running ePassportViewer for user-visible ePassport acquisition and security research. Start "
        "with epassport_recommend_tools or epassport_list_tools, then execute actions through epassport_call."
    ),
)


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def epassport_list_tools(group: str = "", query: str = "", detail: bool = False) -> dict[str, Any]:
    """List lazy ePassport action groups or matching actions; schemas are optional."""

    try:
        return await asyncio.to_thread(bridge.request, "list", {"group": group, "query": query, "detail": detail})
    except ViewerUnavailable as exc:
        return _unavailable(str(exc))


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def epassport_recommend_tools(goal: str, max_actions: int = 8) -> dict[str, Any]:
    """Return a short state-aware workflow and only its required action schemas."""

    try:
        return await asyncio.to_thread(bridge.request, "recommend", {"goal": goal, "max_actions": max_actions})
    except ViewerUnavailable as exc:
        return _unavailable(str(exc))


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
    )
)
async def epassport_call(action: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute one action discovered through the list or recommendation tool."""

    try:
        return await asyncio.to_thread(
            bridge.request, "action", {"action": action, "arguments": dict(arguments or {})}
        )
    except ViewerUnavailable as exc:
        return _unavailable(str(exc), action=action)


def _unavailable(message: str, *, action: str = "") -> dict[str, Any]:
    return {
        "ok": False,
        "action": action,
        "error": {"code": "viewer_unavailable", "message": message},
        "session": {"connected": False, "owner": "ePassportViewer"},
    }


def main() -> None:
    """Run a local, stateful MCP over standard input/output."""

    asyncio.run(run_stdio(mcp))


if __name__ == "__main__":
    main()
