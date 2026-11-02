"""Optional OPA adapter over HTTP. POSTs {"input": {...}} and expects
{"result": {"decision": "allow|deny|require_approval", "reason": str, "policy_id": str}}.
Any transport error, timeout or malformed answer fails closed to deny."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any

from toolpin.policy.decision import Decision, PolicyRequest


def _http(url: str, body: bytes, timeout: float) -> bytes:
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - operator-configured URL
        return r.read(1_000_000)


class OpaPolicy:
    def __init__(self, url: str, timeout: float = 2.0,
                 transport: Callable[[str, bytes, float], bytes] = _http) -> None:
        self.url, self.timeout, self.transport = url, timeout, transport

    def decide(self, req: PolicyRequest) -> Decision:
        body = json.dumps({"input": {"principal": req.principal, "roles": list(req.roles),
                                     "tool": req.tool, "arguments": req.arguments}}).encode()
        try:
            res: dict[str, Any] = json.loads(self.transport(self.url, body, self.timeout))["result"]
            kind = res["decision"]
            if kind not in {"allow", "deny", "require_approval"}:
                raise ValueError(kind)
            return Decision(kind, str(res.get("reason", "opa")), str(res.get("policy_id", "opa")))
        except Exception as e:
            return Decision("deny", f"opa failure: {type(e).__name__}", "opa-error")
