"""Toolpin in front of an Ontolite MCP server (needs `pip install ontolite`, run from the ontolite repo
for the demo data). Reads pass, writes are denied by policy, the audit chain verifies."""
import asyncio

from mcp import Client
from ontolite.ingest.sec_loader import load_sec
from ontolite.mcp_server import build_server
from ontolite.runtime import Ontolite

from toolpin.audit import verify_entries
from toolpin.lockfile import Lockfile
from toolpin.middleware import GateConfig, guard
from toolpin.policy import YamlPolicy

D = "demo/sec"
rt = Ontolite.open(f"{D}/schema.yaml", f"{D}/principals.yaml")
load_sec(rt.schema, rt.store, f"{D}/sample", f"{D}/mappings.yaml")


async def main():
    srv = build_server(rt, "alice")
    lock = Lockfile.lock(await srv.list_tools(), "ontolite")
    pol = YamlPolicy([
        {"id": "reads", "effect": "allow", "tools": ["search", "get", "traverse", "query"]},
        {"id": "writes", "effect": "require_approval", "tools": ["propose_action", "apply_action"]}])
    cfg = GateConfig(lock, pol, principal_fn=lambda c: ("alice", ("analyst",)))
    guard(srv, cfg)
    async with Client(srv) as c:
        print([x["name"] for x in (await c.call_tool("search", {"type": "Company"})).structured_content["result"]])
        print("write blocked (client cannot confirm):", (await c.call_tool("propose_action", {
            "action": "flag_for_review", "params": {"adsh": "0000320193-26-000001", "reason": "x"}})).is_error)
    print("audit ok:", verify_entries(cfg.audit.entries)[0])

asyncio.run(main())
