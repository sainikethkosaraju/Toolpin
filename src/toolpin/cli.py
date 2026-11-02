"""toolpin lock | verify | approve | scan | policy diff | approve-call | audit verify"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from toolpin.audit import verify_file
from toolpin.lockfile import Lockfile
from toolpin.oob import OutOfBandApprovals
from toolpin.policy.decision import PolicyRequest
from toolpin.policy.diff import policy_diff
from toolpin.policy.yaml_rules import YamlPolicy
from toolpin.scan import scan_tool


def _tools(path: str) -> list:
    d = json.loads(Path(path).read_text())
    return d["tools"] if isinstance(d, dict) else d


def _priv(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(Path(path).read_bytes(), password=None)


def _pub(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(Path(path).read_bytes())


def cmd_keygen(a: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    out = Path(a.out)
    out.write_bytes(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    out.chmod(0o600)
    out.with_suffix(".pub").write_bytes(k.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    print(f"wrote {out} (private, 0600) and {out.with_suffix('.pub')}")
    return 0


def cmd_lock(a: argparse.Namespace) -> int:
    lock = Lockfile.lock(_tools(a.tools_json), a.server)
    if a.policy:
        lock.pin_policy(Path(a.policy).read_text())
    lock.save(a.lockfile, _priv(a.sign) if a.sign else None)
    print(f"locked {len(_tools(a.tools_json))} tools -> {a.lockfile}" + (" (signed)" if a.sign else "")
          + (" (policy pinned)" if a.policy else ""))
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    from toolpin.lockfile import SignatureError
    try:
        lock = Lockfile.load(a.lockfile, _pub(a.pubkey) if a.pubkey else None)
    except SignatureError as e:
        print(f"FAILED: {e}")
        return 1
    if a.policy and not lock.verify_policy(Path(a.policy).read_text()):
        print("FAILED: policy file differs from the one pinned in the lockfile")
        return 1
    viol = lock.verify(_tools(a.tools_json))
    for v in viol:
        print(f"{v.kind}: {v.tool} ({v.detail})")
    bad = [v for v in viol if v.blocking]
    print("FAILED" if bad else "ok")
    return 1 if bad else 0


def cmd_approve(a: argparse.Namespace) -> int:
    lock = Lockfile.load(a.lockfile)
    lock.approve(_tools(a.tools_json), a.tool)
    lock.save(a.lockfile)
    print(f"re-pinned {a.tool}")
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    n = 0
    for tool in _tools(a.tools_json):
        for f in scan_tool(tool):
            n += 1
            print(f"{tool['name']}: {f.rule} at {f.where}: {f.detail}")
    print(f"{n} finding(s). Heuristic scan: absence of findings is not a clean bill of health.")
    return 1 if n else 0


def cmd_policy_diff(a: argparse.Namespace) -> int:
    probes = [PolicyRequest(p["principal"], tuple(p.get("roles", [])), p["tool"], p.get("arguments", {}))
              for p in json.loads(Path(a.probes).read_text())]
    out = policy_diff(YamlPolicy.load(a.old), YamlPolicy.load(a.new), probes)
    for k, v in out.items():
        print(f"{k}: {[(p.principal, p.tool) for p in v]}")
    return 1 if out["newly_allowed"] else 0


def cmd_approve_call(a: argparse.Namespace) -> int:
    ok = OutOfBandApprovals(a.store).approve(a.ref)
    print("approved" if ok else "no such pending request (unknown, expired or already handled)")
    return 0 if ok else 1


def cmd_run(a: argparse.Namespace) -> int:
    """Serve a gated proxy on stdio in front of the upstream command (spawned in the configured sandbox)."""
    import anyio

    from toolpin.config import ConfigError, load_config
    from toolpin.proxy import build_proxy, connect_upstream
    try:
        cfg, sandbox = load_config(a.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    cmd = [c for c in a.upstream if c != "--"]
    if not cmd:
        print("give the upstream command after --", file=sys.stderr)
        return 2

    async def main_() -> None:
        async with connect_upstream(cmd[0], sandbox, cmd[1:]) as upstream:
            await build_proxy(upstream, cfg, launch_record=sandbox.launch_record(cmd[0], cmd[1:])).run_stdio_async()
    anyio.run(main_)
    return 0


def cmd_corpus(a: argparse.Namespace) -> int:
    from toolpin import corpus
    results = corpus.run(corpus.load_cases(a.dir, a.split))
    text = corpus.render(results)
    if a.out:
        Path(a.out).write_text(text)
    print(text)
    return 0


def cmd_audit_verify(a: argparse.Namespace) -> int:
    ok, msg = verify_file(a.path, expected_head=a.head)
    print(msg)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="toolpin")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("lock", cmd_lock), ("verify", cmd_verify), ("scan", cmd_scan)):
        s = sub.add_parser(name); s.add_argument("tools_json"); s.add_argument("--lockfile", default="toolpin.lock")
        if name == "lock":
            s.add_argument("--server", default=""); s.add_argument("--sign", help="Ed25519 private key (PEM)")
            s.add_argument("--policy", help="policy file to pin by hash")
        if name == "verify":
            s.add_argument("--pubkey", help="require a valid signature from this key"); s.add_argument("--policy")
        s.set_defaults(fn=fn)
    s = sub.add_parser("keygen"); s.add_argument("--out", default="toolpin.key"); s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("approve"); s.add_argument("tool"); s.add_argument("tools_json")
    s.add_argument("--lockfile", default="toolpin.lock"); s.set_defaults(fn=cmd_approve)
    s = sub.add_parser("policy"); ps = s.add_subparsers(dest="sub", required=True)
    d = ps.add_parser("diff"); d.add_argument("old"); d.add_argument("new"); d.add_argument("probes")
    d.set_defaults(fn=cmd_policy_diff)
    s = sub.add_parser("approve-call"); s.add_argument("ref"); s.add_argument("--store", default="toolpin-oob.json")
    s.set_defaults(fn=cmd_approve_call)
    s = sub.add_parser("run"); s.add_argument("--config", default="toolpin.yaml")
    s.add_argument("upstream", nargs=argparse.REMAINDER); s.set_defaults(fn=cmd_run)
    s = sub.add_parser("corpus"); s.add_argument("--dir", default="corpus"); s.add_argument("--out")
    s.add_argument("--split", choices=["dev", "test"])
    s.set_defaults(fn=cmd_corpus)
    s = sub.add_parser("audit"); au = s.add_subparsers(dest="sub", required=True)
    v = au.add_parser("verify"); v.add_argument("path"); v.add_argument("--head"); v.set_defaults(fn=cmd_audit_verify)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
