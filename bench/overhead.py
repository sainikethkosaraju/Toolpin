"""Measures per-call gate overhead on an in-memory MCP server (no network). Run: python bench/overhead.py"""
import asyncio
import statistics
import time

from mcp import Client
from mcp.server.mcpserver import MCPServer

from toolpin.lockfile import Lockfile
from toolpin.middleware import GateConfig, guard
from toolpin.policy import YamlPolicy

N = 500


def build():
    s = MCPServer("bench")

    @s.tool()
    def echo(text: str) -> str:
        "Echo."
        return text
    return s


async def measure(s):
    async with Client(s) as c:
        for _ in range(20):
            await c.call_tool("echo", {"text": "x"})
        ts = []
        for _ in range(N):
            t0 = time.perf_counter()
            await c.call_tool("echo", {"text": "x"})
            ts.append((time.perf_counter() - t0) * 1000)
    return statistics.median(ts), sorted(ts)[int(0.95 * N)]


async def main():
    base = build()
    gated = build()
    lock = Lockfile.lock(await gated.list_tools())
    guard(gated, GateConfig(lock, YamlPolicy([{"id": "a", "effect": "allow", "tools": ["echo"]}]),
                            constraints={"echo": {"safe_args": ["text"]}}))
    b, g = await measure(base), await measure(gated)
    print(f"ungated median {b[0]:.3f} ms p95 {b[1]:.3f} ms | gated median {g[0]:.3f} ms p95 {g[1]:.3f} ms "
          f"| overhead median {g[0]-b[0]:.3f} ms")

asyncio.run(main())
