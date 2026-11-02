from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Kind = Literal["allow", "deny", "require_approval"]


@dataclass(frozen=True)
class Decision:
    kind: Kind
    reason: str
    policy_id: str

    @property
    def allowed(self) -> bool:
        return self.kind == "allow"


@dataclass(frozen=True)
class PolicyRequest:
    principal: str
    roles: tuple[str, ...]
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)


class PolicyEngine(Protocol):
    def decide(self, req: PolicyRequest) -> Decision: ...
