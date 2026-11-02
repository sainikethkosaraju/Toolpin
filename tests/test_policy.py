import pytest

from toolpin.policy import PolicyRequest, YamlPolicy
from toolpin.policy.cedar_adapter import CedarPolicy
from toolpin.policy.diff import policy_diff
from toolpin.policy.opa_adapter import OpaPolicy

RULES = [
    {"id": "allow-read", "effect": "allow", "tools": ["read_*"]},
    {"id": "deny-etc", "effect": "deny", "tools": ["read_*"], "where": {"path": {"prefix": "/etc"}}},
    {"id": "approve-wipe", "effect": "require_approval", "tools": ["wipe"], "roles": ["admin"]},
    {"id": "cap-pay", "effect": "allow", "tools": ["pay"], "where": {"amount": {"max": 100}}},
]
P = YamlPolicy(RULES)


def req(tool, args=None, who="alice", roles=()):
    return PolicyRequest(who, tuple(roles), tool, args or {})


def test_default_deny_and_reasons():
    d = P.decide(req("unlisted"))
    assert d.kind == "deny" and d.policy_id == "default-deny"
    assert P.decide(req("read_file", {"path": "/data/x"})).kind == "allow"
    d = P.decide(req("read_file", {"path": "/etc/passwd"}))
    assert d.kind == "deny" and d.policy_id == "deny-etc"  # deny overrides allow
    assert P.decide(req("wipe", roles=["admin"])).kind == "require_approval"
    assert P.decide(req("wipe", roles=["user"])).kind == "deny"
    assert P.decide(req("pay", {"amount": 50})).kind == "allow"
    assert P.decide(req("pay", {"amount": 500})).kind == "deny"
    assert P.decide(req("pay", {"amount": "lots"})).kind == "deny"
    assert P.decide(req("pay")).kind == "deny"


def test_bad_rules_rejected():
    with pytest.raises(ValueError):
        YamlPolicy([{"id": "x", "effect": "maybe", "tools": ["*"]}])


CEDAR = '''
@id("allow-read")
permit(principal, action == Action::"call", resource) when { resource == Tool::"read_file" };
@id("deny-etc")
forbid(principal, action, resource == Tool::"read_file") when { context has path && context.path like "/etc*" };
@id("approve-wipe")
permit(principal, action, resource == Tool::"wipe");
'''
SHARED = [req("read_file", {"path": "/data/x"}), req("read_file", {"path": "/etc/passwd"}),
          req("wipe"), req("unlisted"), req("read_file")]


def test_cedar_matches_yaml_on_shared_set():
    y = YamlPolicy([
        {"id": "allow-read", "effect": "allow", "tools": ["read_file"]},
        {"id": "deny-etc", "effect": "deny", "tools": ["read_file"], "where": {"path": {"prefix": "/etc"}}},
        {"id": "approve-wipe", "effect": "require_approval", "tools": ["wipe"]}])
    c = CedarPolicy(CEDAR, approval_ids={"approve-wipe"})
    for r in SHARED:
        assert c.decide(r).kind == y.decide(r).kind, r
    assert c.decide(req("read_file", {"path": "/etc/x"})).policy_id == "deny-etc"
    bad = CedarPolicy("this is not cedar")
    assert bad.decide(req("x")).kind == "deny"  # fails closed


def test_opa_adapter_fail_closed():
    ok = OpaPolicy("http://opa", transport=lambda u, b, t: b'{"result": {"decision": "allow", "reason": "r", "policy_id": "p"}}')
    assert ok.decide(req("x")).kind == "allow"
    for body in (b"not json", b'{"result": {"decision": "yes"}}', b"{}"):
        assert OpaPolicy("http://opa", transport=lambda u, b, t, body=body: body).decide(req("x")).kind == "deny"
    def boom(u, b, t):
        raise TimeoutError()
    assert OpaPolicy("http://opa", transport=boom).decide(req("x")).kind == "deny"


def test_policy_diff_lists_newly_allowed():
    new = YamlPolicy([*RULES, {"id": "open-wipe", "effect": "allow", "tools": ["wipe"]}])
    out = policy_diff(P, new, [req("wipe", roles=["user"]), req("read_file", {"path": "/data"}), req("zzz")])
    assert [p.tool for p in out["newly_allowed"]] == ["wipe"]
    assert policy_diff(new, P, [req("wipe", roles=["user"])])["newly_denied"]
