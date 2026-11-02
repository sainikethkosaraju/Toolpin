"""Optional Cedar adapter (cedarpy, young bindings; install toolpin[cedar]).

Mapping: principal User::"<id>", action Action::"call", resource Tool::"<name>", context = arguments.
Cedar has only permit/forbid, so a permitted request whose determining policy @id is listed in
`approval_ids` becomes require_approval. Any error fails closed to deny."""

from __future__ import annotations

import json
from typing import Any

from toolpin.policy.decision import Decision, PolicyRequest


class CedarPolicy:
    def __init__(self, policies: str, approval_ids: set[str] | None = None) -> None:
        try:
            import cedarpy  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("install toolpin[cedar]") from e
        self.policies, self.approval_ids = policies, approval_ids or set()

    def decide(self, req: PolicyRequest) -> Decision:
        import cedarpy
        try:
            entities: list[dict[str, Any]] = [{
                "uid": {"type": "User", "id": req.principal}, "attrs": {"roles": list(req.roles)},
                "parents": []}]
            res = cedarpy.is_authorized(
                {"principal": f"User::{json.dumps(req.principal)}", "action": 'Action::"call"',
                 "resource": f"Tool::{json.dumps(req.tool)}", "context": req.arguments},
                self.policies, json.dumps(entities))
            ids = [res.diagnostics.id_annotations_by_reason.get(r, r)
                   for r in res.diagnostics.reasons] if res.diagnostics else []
            ids = [i if isinstance(i, str) else str(i) for i in ids]
            pid = ids[0] if ids else "cedar-default-deny"
            if res.diagnostics and res.diagnostics.errors:
                return Decision("deny", "cedar evaluation error", "cedar-error")
            if res.decision == cedarpy.Decision.Allow:
                if any(i in self.approval_ids for i in ids):
                    return Decision("require_approval", f"cedar policy {pid}", pid)
                return Decision("allow", f"cedar policy {pid}", pid)
            return Decision("deny", f"cedar policy {pid}", pid)
        except Exception as e:
            return Decision("deny", f"cedar failure: {type(e).__name__}", "cedar-error")
