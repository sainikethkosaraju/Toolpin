"""toolpin.yaml -> GateConfig (+ Sandbox). Secrets come from environment variables named in the file,
never from the file itself."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from toolpin.approvals import Approvals, SQLiteNonceStore
from toolpin.audit import AuditLog
from toolpin.budgets import Budgets
from toolpin.ifc import IFC, IFCConfig, ToolLabels
from toolpin.lockfile import Lockfile
from toolpin.middleware import GateConfig
from toolpin.oob import OutOfBandApprovals
from toolpin.outputs import OutputPolicy
from toolpin.policy import YamlPolicy
from toolpin.proxy.sandbox import Sandbox


class ConfigError(ValueError):
    pass


def _secret(env: str | None, what: str) -> bytes:
    val = os.environ.get(env or "")
    if not val:
        raise ConfigError(f"{what}: environment variable {env!r} is not set (see .env.example)")
    return val.encode()


def load_config(path: str | Path) -> tuple[GateConfig, Sandbox]:
    base = Path(path).parent
    d: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
    unknown = set(d) - {"lockfile", "lock_pubkey", "policy", "audit", "approvals", "constraints", "budgets", "ifc",
                        "output", "no_mrtr", "oob_store", "sandbox", "principal", "roles"}
    if unknown:
        raise ConfigError(f"unknown keys: {sorted(unknown)}")
    rel = lambda p: str(base / p)  # noqa: E731
    pub = None
    if d.get("lock_pubkey"):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(Path(rel(d["lock_pubkey"])).read_bytes())
    lock = Lockfile.load(rel(d.get("lockfile", "toolpin.lock")), pub)
    if "policy" not in d:
        raise ConfigError("a policy file is required (default deny means nothing works without one)")
    policy_text = Path(rel(d["policy"])).read_text()
    if lock.policy_sha256 is not None and not lock.verify_policy(policy_text):
        raise ConfigError("the policy file differs from the one pinned in the lockfile")
    policy = YamlPolicy(yaml.safe_load(policy_text).get("rules", []))
    ap = d.get("approvals")
    approvals = None
    if ap:
        nonces = SQLiteNonceStore(rel(ap["nonces"])) if ap.get("nonces") else None
        approvals = Approvals(_secret(ap.get("secret_env", "TOOLPIN_APPROVAL_SECRET"), "approvals"),
                              ttl=float(ap.get("ttl", 300)), nonces=nonces)
    ifc = None
    if d.get("ifc"):
        i = d["ifc"]
        tools = {n: ToolLabels(bool(v.get("private")), bool(v.get("untrusted")), bool(v.get("egress")),
                               tuple(v["egress_args"]) if v.get("egress_args") else None)
                 for n, v in (i.get("tools") or {}).items()}
        ifc = IFC(IFCConfig(tools, i.get("trifecta", "require_approval"), i.get("value_flow", "require_approval")),
                  _secret(i.get("secret_env", "TOOLPIN_IFC_SECRET"), "ifc"))
    out = d.get("output")
    audit_key = None
    if d.get("audit", {}).get("signing_key"):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        audit_key = load_pem_private_key(Path(rel(d["audit"]["signing_key"])).read_bytes(), password=None)
    principal, roles = d.get("principal", "anonymous"), tuple(d.get("roles", []))
    b = d.get("budgets") or {}
    cfg = GateConfig(
        lock, policy, approvals, d.get("constraints") or {},
        Budgets(b.get("max_calls_per_tool"), b.get("max_total_calls"), b.get("max_output_bytes"),
                b.get("breaker_threshold", 5), b.get("breaker_cooldown", 30.0)),
        AuditLog(rel(d.get("audit", {}).get("path", "toolpin-audit.jsonl")), audit_key),
        principal_fn=lambda ctx: (principal, roles), no_mrtr=d.get("no_mrtr", "deny"),
        oob=OutOfBandApprovals(rel(d["oob_store"])) if d.get("oob_store") else None, ifc=ifc,
        output=OutputPolicy(bool(out.get("redact", True)), out.get("on_injection", "annotate")) if out else None)
    sb: dict[str, Any] = {k: (tuple(v) if isinstance(v, list) else v) for k, v in (d.get("sandbox") or {}).items()}
    return cfg, Sandbox(**sb)  # type: ignore[arg-type]
