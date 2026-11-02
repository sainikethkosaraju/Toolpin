"""Library mode: wrap an official-SDK `MCPServer` so every listing and call passes the gate.

Pipeline per call: lock check -> policy -> argument constraints -> budgets -> approval (MRTR,
else out-of-band, else deny) -> forward -> output cap -> audit. Every decision is audited.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import mcp_types as t
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from toolpin.approvals import ApprovalError, Approvals
from toolpin.audit import AuditLog
from toolpin.budgets import Budgets
from toolpin.canonical import args_hash, canonical_json, tool_to_dict
from toolpin.constraints import check_arguments
from toolpin.ifc import IFC
from toolpin.lockfile import Lockfile
from toolpin.oob import OutOfBandApprovals
from toolpin.outputs import OutputPolicy, inspect_output
from toolpin.policy.decision import PolicyEngine, PolicyRequest

GENERIC_DENY = "call denied"


@dataclass
class GateConfig:
    lockfile: Lockfile
    policy: PolicyEngine
    approvals: Approvals | None = None
    constraints: dict[str, dict[str, Any]] = field(default_factory=dict)
    budgets: Budgets = field(default_factory=Budgets)
    audit: AuditLog = field(default_factory=AuditLog)
    principal_fn: Callable[[Any], tuple[str, tuple[str, ...]]] = lambda ctx: ("anonymous", ())
    no_mrtr: str = "deny"  # deny | out_of_band
    oob: OutOfBandApprovals | None = None
    ifc: IFC | None = None
    output: OutputPolicy | None = None
    session_fn: Callable[[Any], str] = lambda ctx: "default"


class Gate:
    def __init__(self, server: Any, cfg: GateConfig) -> None:
        self.server, self.cfg = server, cfg
        self._list = server.list_tools
        self._call = server.call_tool
        server.list_tools = self.list_tools
        server.call_tool = self.call_tool

    # -- audit helper
    def _log(self, principal: str, tool: str, decision: str, policy_id: str, reason: str,
             args: dict | None, extra: dict | None = None) -> None:
        self.cfg.audit.append(principal, tool, decision, policy_id, reason, args_hash(args), extra)

    def _deny(self, principal: str, tool: str, policy_id: str, reason: str, args: dict | None,
              public: str | None = None) -> ToolError:
        self._log(principal, tool, "deny", policy_id, reason, args)
        return ToolError(public or f"{GENERIC_DENY}: {policy_id}")

    # -- listing: only pinned, unchanged tools are visible
    async def list_tools(self) -> list[Any]:
        tools = await self._list()
        blocked = set()
        for v in self.cfg.lockfile.verify(tools):
            if v.blocking:
                blocked.add(v.tool)
                self._log("-", v.tool, "deny", "lockfile", f"{v.kind}: {v.detail}", None)
        return [x for x in tools if tool_to_dict(x)["name"] not in blocked]

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None) -> Any:
        cfg = self.cfg
        principal, roles = cfg.principal_fn(context)
        arguments = arguments or {}
        # 1. lock: the tool must be listed, pinned and unchanged RIGHT NOW (rug-pull defence)
        visible = {tool_to_dict(x)["name"] for x in await self.list_tools()}
        if name not in visible:
            raise self._deny(principal, name, "lockfile", "tool unpinned, changed or unknown",
                             arguments, f"{GENERIC_DENY}: tool not trusted")
        # 2. policy (default deny)
        d = cfg.policy.decide(PolicyRequest(principal, roles, name, arguments))
        if d.kind == "deny":
            raise self._deny(principal, name, d.policy_id, d.reason, arguments)
        # 3. constraints
        if (r := check_arguments(arguments, cfg.constraints.get(name, {}))):
            raise self._deny(principal, name, "constraints", r, arguments,
                             f"{GENERIC_DENY}: argument rejected")
        # 4. budgets
        if (r := cfg.budgets.check(name)):
            raise self._deny(principal, name, "budgets", r, arguments)
        # 5. information flow (session memory): may deny, or escalate an allowed call to approval
        sid = f"{principal}:{cfg.session_fn(context)}"
        needs_approval, policy_for_log = d.kind == "require_approval", d.policy_id
        if cfg.ifc is not None:
            v = cfg.ifc.check_call(sid, name, arguments)
            if v.kind == "deny":
                raise self._deny(principal, name, v.rule, v.reason, arguments,
                                 f"{GENERIC_DENY}: {v.rule}")
            if v.kind == "require_approval":
                needs_approval, policy_for_log = True, v.rule
        # 6. approval
        if needs_approval:
            res = self._approve(principal, name, arguments, policy_for_log, context)
            if res is not None:
                return res
        # 7. forward
        try:
            result = await self._call(name, arguments, context)
        except Exception:
            cfg.budgets.record(name, False)
            self._log(principal, name, "error", d.policy_id, "tool raised", arguments)
            raise
        if isinstance(result, t.InputRequiredResult):
            return result
        text = "".join(getattr(c, "text", "") or "" for c in getattr(result, "content", []) or [])
        if cfg.ifc is not None:
            cfg.ifc.observe_result(sid, name, text)                 # fingerprint the ORIGINAL (pre-redaction) text
        if cfg.output is not None and text:
            rep = inspect_output(text, cfg.output)
            if rep.injection and cfg.ifc is not None:               # dynamic labelling: this tool just fed us untrusted text
                cfg.ifc.session(sid).untrusted_exposed = True
            if rep.secrets or rep.injection:
                self._log(principal, name, "inspect", "outputs", f"secrets={rep.secrets} injection={rep.injection}",
                          arguments)
            if rep.blocked:
                raise self._deny(principal, name, "outputs", "instruction-like content in tool result", arguments,
                                 f"{GENERIC_DENY}: tool result rejected")
            if rep.text != text:
                first = True
                for c in result.content:
                    if getattr(c, "text", None) is not None:
                        c.text = rep.text if first else ""
                        first = False
        size = len(text)
        cfg.budgets.record(name, not getattr(result, "is_error", False))
        if (r := cfg.budgets.check_output(size)):
            raise self._deny(principal, name, "budgets", r, arguments, f"{GENERIC_DENY}: output too large")
        self._log(principal, name, "allow", d.policy_id, d.reason, arguments, {"output_bytes": size})
        return result

    def _approve(self, principal: str, name: str, arguments: dict, policy_id: str,
                 context: Any) -> Any:
        """Return None to proceed, an InputRequiredResult to challenge, or raise to deny."""
        cfg = self.cfg
        modern = False
        try:
            modern = context.request_context.protocol_version in MODERN_PROTOCOL_VERSIONS
        except Exception:
            modern = False
        if modern and cfg.approvals is not None:
            state = getattr(context, "request_state", None)
            responses = getattr(context, "input_responses", None)
            if not state:
                token = cfg.approvals.issue(principal, name, arguments)
                msg = (f"Approve call to '{name}' by '{principal}' with arguments "
                       f"{canonical_json(arguments)[:500]}?")
                self._log(principal, name, "challenge", policy_id, "approval requested", arguments)
                return t.InputRequiredResult(
                    input_requests={"confirm": t.ElicitRequest(params=t.ElicitRequestFormParams(
                        message=msg, requested_schema={"type": "object", "properties": {}}))},
                    request_state=token)
            try:
                cfg.approvals.redeem(state, principal, name, arguments)
            except ApprovalError as e:
                raise self._deny(principal, name, "approvals", e.reason, arguments,
                                 f"{GENERIC_DENY}: approval invalid") from None
            confirm = (responses or {}).get("confirm")
            if getattr(confirm, "action", None) != "accept":
                raise self._deny(principal, name, "approvals", "approver declined", arguments,
                                 f"{GENERIC_DENY}: approval declined")
            self._log(principal, name, "approved", policy_id, "mrtr approval redeemed", arguments)
            return None
        if cfg.no_mrtr == "out_of_band" and cfg.oob is not None:
            if cfg.oob.consume(principal, name, arguments):
                self._log(principal, name, "approved", policy_id, "out-of-band approval", arguments)
                return None
            ref = cfg.oob.request(principal, name, arguments)
            self._log(principal, name, "challenge", policy_id, f"out-of-band request {ref}", arguments)
            raise ToolError(f"approval required. Ask an operator to run: toolpin approve-call {ref} "
                            "then retry the identical call")
        raise self._deny(principal, name, "approvals", "client cannot confirm", arguments,
                         f"{GENERIC_DENY}: approval required but client cannot confirm")


def guard(server: Any, cfg: GateConfig) -> Gate:
    return Gate(server, cfg)


__all__ = ["Gate", "GateConfig", "guard", "json"]
