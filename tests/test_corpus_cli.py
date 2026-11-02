import json
from pathlib import Path

from toolpin import corpus
from toolpin.cli import main

ROOT = Path(__file__).parent.parent


def results():
    return corpus.run(corpus.load_cases(ROOT / "corpus"))


def test_corpus_size_and_labels():
    r = results()
    assert len(r) >= 100
    assert sum(x["label"] == "attack" for x in r) >= 60 and sum(x["label"] == "benign" for x in r) >= 30
    cats = {x["category"] for x in r}
    assert {"tool_poisoning", "rug_pull", "shadowing", "ssrf", "argument_injection",
            "confused_deputy", "handle_hijack", "approval_abuse", "benign_call"} <= cats


def test_structural_controls_have_no_misses_or_false_positives():
    conf = corpus.confusion(results())
    for c in corpus.HARD_CONTROLS:
        assert conf[c]["FN"] == 0 and conf[c]["FP"] == 0, (c, conf[c]["misses"], conf[c]["false_positives"])
        assert conf[c]["recall"] == 1.0 and conf[c]["precision"] == 1.0


def test_published_results_are_current_and_include_misses():
    text = corpus.render(results())
    assert (ROOT / "corpus" / "RESULTS.md").read_text() == text, "run: toolpin corpus --out corpus/RESULTS.md"
    conf = corpus.confusion(results())
    assert sum(m["FN"] for m in conf.values()) > 0  # heuristics do miss; the report must say so
    for m in conf.values():
        for miss in m["misses"] + m["false_positives"]:
            assert miss["id"] in text


def test_cli_lock_verify_scan_approve(tmp_path, capsys):
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps({"tools": [{"name": "a", "description": "ok"}]}))
    lock = str(tmp_path / "toolpin.lock")
    assert main(["lock", str(tools), "--lockfile", lock]) == 0
    assert main(["verify", str(tools), "--lockfile", lock]) == 0
    tools.write_text(json.dumps({"tools": [{"name": "a", "description": "ok <IMPORTANT>x</IMPORTANT>"}]}))
    assert main(["verify", str(tools), "--lockfile", lock]) == 1
    assert main(["scan", str(tools)]) == 1
    assert main(["approve", "a", str(tools), "--lockfile", lock]) == 0
    assert main(["verify", str(tools), "--lockfile", lock]) == 0


def test_cli_policy_diff_oob_and_audit(tmp_path, capsys):
    old, new = tmp_path / "o.yaml", tmp_path / "n.yaml"
    old.write_text("rules: [{id: r1, effect: allow, tools: [read_*]}]")
    new.write_text("rules: [{id: r1, effect: allow, tools: [read_*]}, {id: r2, effect: allow, tools: [wipe]}]")
    probes = tmp_path / "p.json"
    probes.write_text(json.dumps([{"principal": "a", "tool": "wipe"}, {"principal": "a", "tool": "read_x"}]))
    assert main(["policy", "diff", str(old), str(new), str(probes)]) == 1
    assert "newly_allowed: [('a', 'wipe')]" in capsys.readouterr().out
    from toolpin.oob import OutOfBandApprovals
    store = tmp_path / "oob.json"
    ref = OutOfBandApprovals(store).request("a", "wipe", {"p": 1})
    assert main(["approve-call", ref, "--store", str(store)]) == 0
    assert main(["approve-call", "nope", "--store", str(store)]) == 1
    from toolpin.audit import AuditLog
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("a", "t", "allow", "p", "r", "d")
    assert main(["audit", "verify", str(tmp_path / "a.jsonl")]) == 0
    (tmp_path / "a.jsonl").write_text((tmp_path / "a.jsonl").read_text().replace('"allow"', '"deny"'))
    assert main(["audit", "verify", str(tmp_path / "a.jsonl")]) == 1
