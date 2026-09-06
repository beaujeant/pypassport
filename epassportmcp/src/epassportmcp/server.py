"""Model Context Protocol stdio server for AI-assisted ePassport research."""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .controller import ActionError, PassportController
from .stdio import run_stdio

controller = PassportController()
mcp = MCPServer(
    "ePassportViewer",
    instructions=(
        "AI-assisted ePassport acquisition and security research. Start with epassport_recommend_tools for a goal "
        "or epassport_list_tools for a compact catalog, then execute lazy actions through epassport_call."
    ),
)


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def epassport_list_tools(group: str = "", query: str = "", detail: bool = False) -> dict[str, Any]:
    """List lazy ePassport action groups or matching actions; schemas are optional."""

    try:
        return controller.list_actions(group=group, query=query, detail=detail)
    except ActionError as exc:
        return controller.error_payload("epassport_list_tools", exc)


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def epassport_recommend_tools(goal: str, max_actions: int = 8) -> dict[str, Any]:
    """Return a short state-aware workflow and only its required action schemas."""

    return controller.recommend(goal, max_actions=max_actions)


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
    )
)
async def epassport_call(action: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute one action discovered through the list or recommendation tool."""

    try:
        return await asyncio.to_thread(controller.execute, action, arguments)
    except ActionError as exc:
        return controller.error_payload(action, exc)


def main() -> None:
    """Run a local, stateful MCP over standard input/output."""

    asyncio.run(run_stdio(mcp))


if __name__ == "__main__":
    main()
