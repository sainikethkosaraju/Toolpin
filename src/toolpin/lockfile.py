"""toolpin.lock: SHA-256 per tool definition. verify() reports changed / added / removed."""

from __future__ import annotations

import hashlib
import hmac
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


class SignatureError(ValueError):
    pass


class Lockfile:
    def __init__(self, tools: dict[str, dict[str, str]] | None = None, server: str = "",
                 policy_sha256: str | None = None) -> None:
        self.tools = tools or {}
        self.server = server
        self.policy_sha256 = policy_sha256

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

    def pin_policy(self, policy_text: str) -> None:
        """Bind this lock to the exact policy file, so loosening the policy is as visible as changing a tool."""
        self.policy_sha256 = hashlib.sha256(policy_text.encode()).hexdigest()

    def verify_policy(self, policy_text: str) -> bool:
        return self.policy_sha256 is not None and hmac.compare_digest(
            self.policy_sha256, hashlib.sha256(policy_text.encode()).hexdigest())

    def _body(self) -> dict[str, Any]:
        return {"toolpin": 1, "server": self.server, "tools": self.tools, "policy_sha256": self.policy_sha256}

    def to_json(self, signing_key: Any = None) -> str:
        body = self._body()
        if signing_key is not None:
            payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            body = {**body, "signature": signing_key.sign(payload).hex()}
        return json.dumps(body, indent=2, sort_keys=True) + "\n"

    def save(self, path: str | Path, signing_key: Any = None) -> None:
        Path(path).write_text(self.to_json(signing_key))

    @classmethod
    def load(cls, path: str | Path, public_key: Any = None) -> Lockfile:
        """With `public_key`, the lockfile MUST carry a valid Ed25519 signature (unsigned == rejected)."""
        d: dict[str, Any] = json.loads(Path(path).read_text())
        if d.get("toolpin") != 1:
            raise ValueError("unsupported lockfile version")
        if public_key is not None:
            sig = d.get("signature")
            if not sig:
                raise SignatureError("lockfile is unsigned but a public key was required")
            body = {k: v for k, v in d.items() if k != "signature"}
            try:
                public_key.verify(bytes.fromhex(sig), json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
            except Exception:
                raise SignatureError("lockfile signature is invalid (edited, or signed by another key)") from None
        return cls(d["tools"], d.get("server", ""), d.get("policy_sha256"))
