"""toolpin.lock: SHA-256 per tool definition. verify() reports changed / added / removed."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from toolpin.canonical import tool_hash, tool_to_dict


@dataclass(frozen=True)
class Violation:
    kind: str  # changed | added | removed
    tool: str
    detail: str = ""

    @property
    def blocking(self) -> bool:
        return self.kind in {"changed", "added"}


class Lockfile:
    def __init__(self, tools: dict[str, dict[str, str]] | None = None, server: str = "") -> None:
        self.tools = tools or {}
        self.server = server

    @classmethod
    def lock(cls, tools: list[Any], server: str = "") -> Lockfile:
        out: dict[str, dict[str, str]] = {}
        for t in tools:
            d = tool_to_dict(t)
            if d["name"] in out:
                raise ValueError(f"duplicate tool name in listing: {d['name']!r}")
            out[d["name"]] = {"sha256": tool_hash(d), "description": str(d.get("description", ""))[:80]}
        return cls(out, server)

    def verify(self, tools: list[Any]) -> list[Violation]:
        seen: dict[str, str] = {}
        v: list[Violation] = []
        for t in tools:
            d = tool_to_dict(t)
            n = d["name"]
            if n in seen:
                v.append(Violation("added", n, "duplicate name in listing"))
                continue
            seen[n] = tool_hash(d)
            if n not in self.tools:
                v.append(Violation("added", n, "tool is not in the lockfile"))
            elif self.tools[n]["sha256"] != seen[n]:
                v.append(Violation("changed", n, "definition differs from the locked hash"))
        v += [Violation("removed", n, "locked tool no longer listed") for n in self.tools if n not in seen]
        return v

    def diff(self, tools: list[Any]) -> list[str]:
        return [f"{x.kind}: {x.tool} ({x.detail})" for x in self.verify(tools)]

    def approve(self, tools: list[Any], name: str) -> None:
        """Accept the CURRENT definition of one tool after human review."""
        for t in tools:
            d = tool_to_dict(t)
            if d["name"] == name:
                self.tools[name] = {"sha256": tool_hash(d), "description": str(d.get("description", ""))[:80]}
                return
        raise KeyError(name)

    def to_json(self) -> str:
        return json.dumps({"toolpin": 1, "server": self.server, "tools": self.tools},
                          indent=2, sort_keys=True) + "\n"

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json())

    @classmethod
    def load(cls, path: str | Path) -> Lockfile:
        d: dict[str, Any] = json.loads(Path(path).read_text())
        if d.get("toolpin") != 1:
            raise ValueError("unsupported lockfile version")
        return cls(d["tools"], d.get("server", ""))
