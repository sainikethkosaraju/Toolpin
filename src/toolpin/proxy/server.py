"""Proxy mode: a gated MCP server in front of ANY upstream MCP server (stdio subprocess or HTTP URL).

The downstream side is an official-SDK `MCPServer` whose listing and call handlers are replaced by
the same `Gate` pipeline used in library mode; the upstream side is an SDK `Client`. Every call
re-lists upstream tools first, so a definition that changes mid-session (rug pull) is caught at the
next call, across the process boundary."""
from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Any

from mcp import Client, StdioServerParameters
from mcp.server.mcpserver import MCPServer

from toolpin.middleware import Gate, GateConfig
from toolpin.proxy.sandbox import Sandbox


class UpstreamBackend:
    """Presents an upstream `Client` with the two methods the Gate wraps."""

    def __init__(self, client: Client) -> None:
        self.client = client

    async def list_tools(self) -> list[Any]:
        tools: list[Any] = []
        cursor = None
        while True:
            res = await self.client.list_tools(cursor=cursor) if cursor else await self.client.list_tools()
            tools += list(res.tools)
            cursor = getattr(res, "next_cursor", None)
            if not cursor:
                return tools

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None) -> Any:
        return await self.client.call_tool(name, arguments)


def connect_upstream(target: str | StdioServerParameters, sandbox: Sandbox | None = None,
                     command_args: list[str] | None = None) -> AbstractAsyncContextManager[Client]:
    """`target` is a URL (HTTP upstream) or a command (stdio upstream, spawned inside `sandbox`)."""
    if isinstance(target, str) and target.startswith(("http://", "https://")):
        return Client(target)
    if isinstance(target, StdioServerParameters):
        return Client(target)
    sb = sandbox or Sandbox()
    return Client(sb.params(target, command_args))


def build_proxy(upstream: Client, cfg: GateConfig, name: str = "toolpin-proxy",
                launch_record: dict[str, Any] | None = None) -> MCPServer:
    """Return a downstream MCPServer. Use `server.run("stdio")` to serve a host, or hand it to a Client."""
    server = MCPServer(name)
    backend = UpstreamBackend(upstream)
    server.list_tools = backend.list_tools          # type: ignore[method-assign]
    server.call_tool = backend.call_tool            # type: ignore[method-assign]
    Gate(server, cfg)
    if launch_record is not None:
        cfg.audit.append("toolpin", "<launch>", "launch", "sandbox", "upstream started",
                         launch_record["argv_sha256"], {k: v for k, v in launch_record.items() if k != "argv_sha256"})
    return server
