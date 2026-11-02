"""Built-in rule engine. Default deny. Precedence: any matching deny > any matching
require_approval > any matching allow > default deny."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

from toolpin.policy.decision import Decision, PolicyRequest

EFFECTS = {"allow", "deny", "require_approval"}
DEFAULT = Decision("deny", "no rule allows this call (default deny)", "default-deny")


def _match_where(where: dict[str, Any], args: dict[str, Any]) -> bool:
    for arg, cond in (where or {}).items():
        if arg not in args:
            return False
        v = args[arg]
        for op, want in (cond if isinstance(cond, dict) else {"equals": cond}).items():
            try:
                ok = {
                    "equals": lambda: v == want, "in": lambda: v in want,
                    "max": lambda: v <= want, "min": lambda: v >= want,
                    "gt": lambda: v > want, "lt": lambda: v < want,
                    "pattern": lambda: isinstance(v, str) and re.fullmatch(want, v) is not None,
                    "prefix": lambda: isinstance(v, str) and v.startswith(want),
                }[op]()
            except (TypeError, KeyError):
                return False
            if not ok:
                return False
    return True


class YamlPolicy:
    def __init__(self, rules: list[dict[str, Any]]) -> None:
        for r in rules:
            if r.get("effect") not in EFFECTS or "id" not in r:
                raise ValueError(f"bad rule (need id and effect in {sorted(EFFECTS)}): {r}")
        self.rules = rules

    @classmethod
    def load(cls, path: str | Path) -> YamlPolicy:
        return cls((yaml.safe_load(Path(path).read_text()) or {}).get("rules", []))

    def _applies(self, r: dict[str, Any], req: PolicyRequest) -> bool:
        if not any(fnmatch.fnmatchcase(req.tool, p) for p in r.get("tools", [])):
            return False
        pr = r.get("principals", ["*"])
        if not any(fnmatch.fnmatchcase(req.principal, p) for p in pr):
            return False
        if r.get("roles") and not set(r["roles"]) & set(req.roles):
            return False
        return _match_where(r.get("where", {}), req.arguments)

    def decide(self, req: PolicyRequest) -> Decision:
        hits = [r for r in self.rules if self._applies(r, req)]
        for effect in ("deny", "require_approval", "allow"):
            for r in hits:
                if r["effect"] == effect:
                    return Decision(effect, r.get("reason", f"matched rule {r['id']}"), r["id"])  # type: ignore[arg-type]
        return DEFAULT
