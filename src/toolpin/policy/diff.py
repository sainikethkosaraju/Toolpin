"""Policy change analysis: which probed calls are NEWLY allowed (or newly require approval)."""

from __future__ import annotations

from toolpin.policy.decision import PolicyEngine, PolicyRequest

RANK = {"deny": 0, "require_approval": 1, "allow": 2}


def policy_diff(old: PolicyEngine, new: PolicyEngine, probes: list[PolicyRequest],
                ) -> dict[str, list[PolicyRequest]]:
    out: dict[str, list[PolicyRequest]] = {"newly_allowed": [], "newly_denied": [], "loosened": []}
    for p in probes:
        a, b = old.decide(p).kind, new.decide(p).kind
        if a != "allow" and b == "allow":
            out["newly_allowed"].append(p)
        elif a != "deny" and b == "deny":
            out["newly_denied"].append(p)
        if RANK[b] > RANK[a]:
            out["loosened"].append(p)
    return out
