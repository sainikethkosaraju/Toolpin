"""Corpus runner: evaluates every labelled case against exactly the control it targets and
renders a confusion matrix per control, with every miss (FN) and false positive (FP) listed."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import yaml

from toolpin.approvals import ApprovalError, Approvals
from toolpin.constraints import check_injection, check_number, check_path, check_url
from toolpin.identity import (
    HandleBinder,
    IdentityError,
    assert_no_passthrough,
    validate_claims,
    verify_hs256_jwt,
)
from toolpin.lockfile import Lockfile
from toolpin.policy import PolicyRequest, YamlPolicy
from toolpin.scan import check_shadowing, scan_tool

POLICY_RULES = [
    {"id": "allow-read", "effect": "allow", "tools": ["read_*"]},
    {"id": "deny-etc", "effect": "deny", "tools": ["read_file"], "where": {"path": {"prefix": "/etc"}}},
    {"id": "allow-pay", "effect": "allow", "tools": ["pay"], "where": {"amount": {"max": 100}}},
    {"id": "allow-search", "effect": "allow", "tools": ["search"]},
    {"id": "allow-admin", "effect": "allow", "tools": ["admin_reset"], "roles": ["admin"]},
]
# Controls whose guarantees are cryptographic / structural: the corpus must show zero misses.
HARD_CONTROLS = ("lockfile", "approval", "handle", "identity")


def _jwt(alg: str, key: bytes) -> str:
    import hashlib
    import hmac
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    h, p = b({"alg": alg}), b({"aud": "https://srv", "iss": "idp", "exp": 2000, "sub": "alice"})
    sig = base64.urlsafe_b64encode(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig.decode().rstrip('=')}"


def _blocked(case: dict[str, Any]) -> bool:
    c, i = case["control"], case["input"]
    if c == "scan":
        return bool(scan_tool(i["tool"]))
    if c == "lockfile":
        lock = Lockfile.lock([i["original"]])
        return any(v.blocking for v in lock.verify(i["current"]))
    if c == "shadow":
        return bool(check_shadowing(i["name"], i["known"]))
    if c == "url":
        return check_url(i["url"]) is not None
    if c == "path":
        return check_path(i["path"], ["/data"]) is not None
    if c == "args":
        if "amount" in i:
            return check_number(i["amount"], ceiling=i["ceiling"]) is not None
        return check_injection(i["value"]) is not None
    if c == "identity":
        try:
            if "claims" in i:
                validate_claims(i["claims"], "https://srv", {"idp"}, now=1000)
            elif "jwt_alg" in i:
                key = b"k" * 32 if i.get("jwt_key", "right") == "right" else b"x" * 32
                verify_hs256_jwt(_jwt(i["jwt_alg"], key), b"k" * 32)
            else:
                assert_no_passthrough(i["passthrough"], i["inbound"])
            return False
        except IdentityError:
            return True
    if c == "handle":
        now = [0.0]
        hb = HandleBinder(b"h" * 32, ttl=10, clock=lambda: now[0])
        bound = hb.bind("cursor-1", "alice")
        m = i["mutate"]
        presented = {"none": bound, "guess": "cursor-2.99.0000", "bare": "cursor-1", "empty": "",
                     "swap_id": bound.replace("cursor-1", "cursor-2"),
                     "extend_exp": bound.replace(f".{10}.", ".99999."),
                     "truncate": bound[:-10]}[m]
        now[0] = float(i.get("at", 5))
        try:
            hb.check(presented, i["presented_by"])
            return False
        except IdentityError:
            return True
    if c == "approval":
        now = [0.0]
        ap = Approvals("c" * 40, ttl=300, clock=lambda: now[0])
        base = {"path": "/data/x", "n": 1}
        tok = ap.issue("alice", "wipe", base)
        m = i["mutate"]
        if m == "literal_true":
            tok = "true"
        elif m == "flip_sig":
            tok = tok[:-1] + ("A" if tok[-1] != "A" else "B")
        elif m == "empty":
            tok = ""
        elif m == "payload_only":
            tok = tok.split(".")[0]
        elif m == "other_key":
            tok = Approvals("d" * 40, clock=lambda: now[0]).issue("alice", "wipe", base)
        elif m == "extend_exp":
            body, sig = tok.split(".")
            raw = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            raw["e"] += 10**6
            nb = base64.urlsafe_b64encode(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode())
            tok = nb.decode().rstrip("=") + "." + sig
        now[0] = float(i.get("at", 1))
        args, tool, who = i.get("args", base), i.get("tool", "wipe"), i.get("principal", "alice")
        try:
            if m == "replay":
                ap.redeem(tok, "alice", "wipe", base)
            ap.redeem(tok, who, tool, args)
            return False
        except ApprovalError:
            return True
    if c == "policy":
        d = YamlPolicy(POLICY_RULES).decide(PolicyRequest(
            "alice", tuple(i.get("roles", ())), i["tool"], i.get("arguments", {})))
        return d.kind != "allow"
    raise ValueError(f"unknown control {c}")


def load_cases(corpus_dir: str | Path, split: str | None = None) -> list[dict[str, Any]]:
    """`corpus_dir` holds `dev/` (hardening may look at it) and `test/` (held out, frozen by hash).
    With split=None both are loaded and each case is tagged with its split."""
    root = Path(corpus_dir)
    cases: list[dict[str, Any]] = []
    splits = [split] if split else [d.name for d in sorted(root.iterdir()) if d.is_dir()] or [""]
    for sp in splits:
        for f in sorted((root / sp).glob("*.yaml")):
            cases += [{**c, "split": sp or "dev"} for c in yaml.safe_load(f.read_text())]
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids")
    for c in cases:
        if c["label"] not in {"attack", "benign"}:
            raise ValueError(f"{c['id']}: bad label")
    return cases


def run(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**c, "blocked": _blocked(c)} for c in cases]


def confusion(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in results:
        m = out.setdefault(r["control"], {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "misses": [], "false_positives": []})
        if r["label"] == "attack":
            m["TP" if r["blocked"] else "FN"] += 1
            if not r["blocked"]:
                m["misses"].append(r)
        else:
            m["FP" if r["blocked"] else "TN"] += 1
            if r["blocked"]:
                m["false_positives"].append(r)
    for m in out.values():
        tp, fn, fp = m["TP"], m["FN"], m["FP"]
        m["precision"] = tp / (tp + fp) if tp + fp else None
        m["recall"] = tp / (tp + fn) if tp + fn else None
    return out


def render(results: list[dict[str, Any]]) -> str:
    fmt = lambda x: "n/a" if x is None else f"{x:.2f}"  # noqa: E731
    lines = ["# Corpus results", "",
             f"{len(results)} labelled cases ({sum(r['label'] == 'attack' for r in results)} attacks, "
             f"{sum(r['label'] == 'benign' for r in results)} benign). Generated by `toolpin corpus`; "
             "do not edit by hand (a test fails if this file is stale).", ""]
    for sp in sorted({r.get("split", "dev") for r in results}):
        sub = [r for r in results if r.get("split", "dev") == sp]
        lines += [f"## Split: `{sp}` ({len(sub)} cases)" + (" - held out, frozen by hash before hardening" if sp == "test" else ""),
                  "", "| control | TP | FN (missed attacks) | FP (benign blocked) | TN | precision | recall |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        for c, m in sorted(confusion(sub).items()):
            lines.append(f"| {c} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | "
                         f"{fmt(m['precision'])} | {fmt(m['recall'])} |")
        lines.append("")
    lines += ["## Misses (attacks that were NOT blocked)", ""]
    miss = [r for r in results if r["label"] == "attack" and not r["blocked"]]
    lines += [f"- `{r['id']}` [{r['control']}] {r.get('note', r['category'])}" for r in miss] or ["- none"]
    lines += ["", "## False positives (benign cases that were blocked)", ""]
    fps = [r for r in results if r["label"] == "benign" and r["blocked"]]
    lines += [f"- `{r['id']}` [{r['control']}] {r.get('note', r['category'])}" for r in fps] or ["- none"]
    lines += ["", "Interpretation: `lockfile`, `approval`, `handle` and `identity` are structural/cryptographic "
              "and must show zero misses. `scan`, `args`, `url`, `shadow` and `policy` are heuristics or "
              "configuration-dependent; their misses are published, not hidden.", ""]
    return "\n".join(lines)
