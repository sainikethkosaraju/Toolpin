import json
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

UP = str(Path(__file__).parent / "fixtures" / "upstream_server.py")


async def write_project(tmp_path, ifc=True):
    from mcp import Client as C

    from toolpin.cli import main
    # lock the REAL upstream by listing it once
    async def listing():
        async with C(StdioServerParameters(command=sys.executable, args=[UP])) as c:
            return [t.model_dump(by_alias=True, exclude_none=True, mode="json") for t in (await c.list_tools()).tools]
    tools = await listing()
    (tmp_path / "tools.json").write_text(json.dumps({"tools": tools}))
    (tmp_path / "policy.yaml").write_text(
        "rules:\n  - {id: ok, effect: allow, tools: ['*']}\n")
    cfg = ("lockfile: toolpin.lock\npolicy: policy.yaml\naudit: {path: audit.jsonl}\n"
           "principal: alice\nsandbox: {as_mb: 1024, nofile: 256}\noutput: {on_injection: annotate}\n")
    if ifc:
        cfg += ("ifc:\n  trifecta: deny\n  value_flow: deny\n  tools:\n    read_secret: {private: true}\n"
                "    fetch_page: {untrusted: true}\n    send_email: {egress: true}\n")
    (tmp_path / "toolpin.yaml").write_text(cfg)
    assert main(["lock", str(tmp_path / "tools.json"), "--lockfile", str(tmp_path / "toolpin.lock"),
                 "--policy", str(tmp_path / "policy.yaml")]) == 0


async def test_toolpin_run_end_to_end_over_real_stdio(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLPIN_IFC_SECRET", "x" * 32)
    await write_project(tmp_path)
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "toolpin.cli", "run", "--config", str(tmp_path / "toolpin.yaml"), "--",
                                         sys.executable, UP],
                                   env={"TOOLPIN_IFC_SECRET": "x" * 32, "PATH": __import__("os").environ["PATH"]})
    async with Client(params) as c:                           # client -> toolpin (process) -> sandboxed upstream (process)
        assert (await c.call_tool("echo", {"text": "hi"})).content[0].text == "hi"
        await c.call_tool("read_secret", {"name": "prod"})
        r = await c.call_tool("send_email", {"to": "x@y.z", "body": "sk-live-4f9a7c21b8e5d3"})
        assert r.is_error and "ifc-value-flow" in r.content[0].text
    from toolpin.audit import verify_file
    ok, _ = verify_file(tmp_path / "audit.jsonl")
    assert ok and (tmp_path / "audit.jsonl").read_text().count("\n") >= 4


async def test_config_errors_fail_closed(tmp_path, monkeypatch):
    from toolpin.config import ConfigError, load_config
    monkeypatch.delenv("TOOLPIN_IFC_SECRET", raising=False)
    await write_project(tmp_path)
    with pytest.raises(ConfigError, match="TOOLPIN_IFC_SECRET"):
        load_config(tmp_path / "toolpin.yaml")
    monkeypatch.setenv("TOOLPIN_IFC_SECRET", "x" * 32)
    load_config(tmp_path / "toolpin.yaml")
    (tmp_path / "policy.yaml").write_text("rules: [{id: open, effect: allow, tools: ['*'], principals: ['*']}, {id: more, effect: allow, tools: ['x']}]\n")
    with pytest.raises(ConfigError, match="differs from the one pinned"):
        load_config(tmp_path / "toolpin.yaml")                     # policy loosened after locking
    (tmp_path / "toolpin.yaml").write_text("polcy: typo.yaml\n")
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config(tmp_path / "toolpin.yaml")
    (tmp_path / "toolpin.yaml").write_text("lockfile: toolpin.lock\n")
    with pytest.raises(ConfigError, match="policy file is required"):
        load_config(tmp_path / "toolpin.yaml")


async def test_stack_benchmark_attacks_succeed_without_toolpin_and_not_with_it():
    pytest.importorskip("ontolite")
    sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
    import stack_bench as sb
    res = await sb.run_all()
    a, w = res["attacks"], res["workflows"]
    applicable = [v for k, v in a.items() if not k.startswith("forged-approval")]
    assert sum(v["without"] for v in applicable) >= 9                      # the attacks are real
    assert sum(v["with"] for v in a.values()) == 0                          # and Toolpin stops all of them
    assert all(v["with"] for v in w.values()) and all(v["without"] for v in w.values())   # without breaking benign work
    assert (Path(__file__).parent.parent / "docs" / "stack-bench.md").read_text() == sb.render(res), \
        "run: python bench/stack_bench.py --md"
