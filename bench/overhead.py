"""Measures per-call gate overhead on an in-memory MCP server (no network). Run: python bench/overhead.py"""
import asyncio
import statistics
import time

from mcp import Client
from mcp.server.mcpserver import MCPServer

from toolpin.ifc import IFC, IFCConfig, ToolLabels
from toolpin.lockfile import Lockfile
from toolpin.middleware import GateConfig, guard
from toolpin.outputs import OutputPolicy
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
    basic = build()
    full = build()
    pol = YamlPolicy([{"id": "a", "effect": "allow", "tools": ["echo"]}])
    guard(basic, GateConfig(Lockfile.lock(await basic.list_tools()), pol, constraints={"echo": {"safe_args": ["text"]}}))
    guard(full, GateConfig(Lockfile.lock(await full.list_tools()), pol, constraints={"echo": {"safe_args": ["text"]}},
                           ifc=IFC(IFCConfig(tools={"echo": ToolLabels(private=True)}), b"k" * 32), output=OutputPolicy()))
    b, g1, g2 = await measure(base), await measure(basic), await measure(full)
    print(f"ungated        median {b[0]:.3f} ms  p95 {b[1]:.3f} ms")
    print(f"basic gate     median {g1[0]:.3f} ms  p95 {g1[1]:.3f} ms  (+{g1[0]-b[0]:.3f} ms)  lockfile + policy + constraints")
    print(f"full gate      median {g2[0]:.3f} ms  p95 {g2[1]:.3f} ms  (+{g2[0]-b[0]:.3f} ms)  + IFC fingerprinting + output inspection")

asyncio.run(main())
