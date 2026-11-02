<h1 align="center">Toolpin</h1>

<p align="center"><b>A session-aware gate for MCP tool use.</b><br>Information-flow control, call-bound approvals, a sandboxed proxy, and a red-team report that publishes what it misses.</p>

<p align="center">
  <a href="https://github.com/sainikethkosaraju/toolpin/actions/workflows/ci.yml"><img src="https://github.com/sainikethkosaraju/toolpin/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license">
</p>

<p align="center"><a href="#quickstart">Quickstart</a> · <a href="#the-gate">The gate</a> · <a href="#evidence">Evidence</a> · <a href="#limitations">Limitations</a> · <a href="docs/redteam.md">Red-team report</a> · <a href="docs/landscape.md">Landscape</a></p>

---
A session-aware gate for MCP tool use. It sits between an agent and its tools (as a library around an official-SDK `MCPServer`, or as a sandboxed stdio proxy in front of *any* server) and decides each call with **memory of what the session has already seen**: pinned definitions, default-deny policy, call-bound human approvals, **information-flow control** for the "lethal trifecta", and inspection of tool results.

> **Positioning (verified by a web search, not assumed):** tool-definition *lockfiles* already exist (`mcp-pin`, `heldfast`, `mcp-warden`, `vex-mcp`; see [docs/landscape.md](docs/landscape.md)). Toolpin has one, signed and policy-pinned, but does not rest on it. Its value is what happens *between* calls.

## Quickstart

```bash
pip install -e ".[dev]"
toolpin lock tools.json --sign toolpin.key --policy policy.yaml        # pin definitions + policy (toolpin keygen first)
TOOLPIN_APPROVAL_SECRET=... TOOLPIN_IFC_SECRET=... toolpin run --config toolpin.yaml -- python my_server.py
toolpin corpus                                                         # attack corpus with misses listed
```
```python
guard(server, GateConfig(lock, policy, Approvals(secret, nonces=SQLiteNonceStore("n.db")),
                         ifc=IFC(IFCConfig(tools={"read_secret": ToolLabels(private=True),
                                                  "fetch_page": ToolLabels(untrusted=True),
                                                  "send_email": ToolLabels(egress=True)}), ifc_secret),
                         output=OutputPolicy()))
```

## The gate
```
client -> [ lock check (re-list upstream every call) -> policy (default deny) -> argument constraints -> budgets
            -> information-flow (trifecta / value flow) -> approval (MRTR token | out-of-band | deny) -> forward
            -> result inspection (redact secrets, annotate/block injection, label session) -> audit ] -> tool
```
- **Information-flow control** ([docs/ifc.md](docs/ifc.md)): an egress call after the session read private data *and* ingested untrusted content needs approval; arguments containing fingerprinted private data (incl. base64/hex/percent copies, figures like `48,215`) are stopped regardless.
- **Approvals** ([docs/approval-protocol.md](docs/approval-protocol.md)): HMAC token bound to principal + tool + canonical argument hash + nonce + expiry + key id; durable single-use nonces (SQLite, safe across worker processes); key rotation; MRTR for 2026-07-28 clients, out-of-band for older ones.
- **Proxy** ([docs/proxy.md](docs/proxy.md)): sandboxed upstream spawn (scrubbed env, rlimits, `no_new_privs`, optional `bwrap`), rug pulls caught across a real process boundary.
- **Identity**: JWKS RS256/ES256 verification with an algorithm allow-list, audience = this resource, RFC 9728 metadata. **Lockfile**: Ed25519-signed, policy-pinned.

## Evidence
| Claim | Evidence |
| --- | --- |
| Stack benchmark: **10/10 applicable attacks succeed on an unprotected Ontolite server; 0/11 with Toolpin; 4/4 benign workflows still complete** (with a human approver) | [docs/stack-bench.md](docs/stack-bench.md), `bench/stack_bench.py`, `tests/test_cli_proxy_and_stack.py` |
| The benchmark found a real hole (a base64 copy of a short figure evaded value-flow); fixed and regression-tested | `tests/test_ifc.py` (`test_figures_are_tracked...`) |
| Red-team: mutation-fuzzer evasion fell from 12-37% to ~0% on known operators, **but 7-71% on operators written afterwards** (overfitting measured, not hidden) | [docs/redteam.md](docs/redteam.md) |
| Held-out corpus (108 cases, frozen by hash before hardening): recall rose, precision held | [docs/redteam.md](docs/redteam.md), [corpus/RESULTS.md](corpus/RESULTS.md) |
| Approval forgery/replay/tamper/expiry/wrong-key rejected; exactly 1 of 24 concurrent redemptions wins | `tests/test_core.py`, `tests/test_hardening.py` |
| Real subprocess: rug pull caught mid-session; env scrubbed (checked from inside the child); rlimits and `no_new_privs` really applied | `tests/test_proxy.py` |
| JWKS rejects alg=none, HS256 key confusion, wrong kid/audience/issuer, expired, replay | `tests/test_hardening.py` |
| Gate overhead: +0.15 ms (lockfile+policy+constraints), +0.26 ms (with IFC and result inspection) | `bench/overhead.py`, [docs/limits.md](docs/limits.md) |
| Coverage 87% overall; approvals/identity/lockfile/outputs/scan >= 94%; `proxy/launch.py` runs in a child process so coverage does not see it | `pytest --cov` |

## Limitations
Read [docs/threat-model.md](docs/threat-model.md). Highlights: a server that is malicious at lock time and never changes is not caught by pinning; the heuristics (scan, SSRF, injection) have published misses and false positives; IFC cannot see paraphrase; SSRF is static; the sandbox is not a boundary against a determined attacker; `bwrap` was **not available** in the build sandbox so that path is untested beyond argument construction; the corpus, fuzzer and held-out set share one author; benchmarks use scripted attackers, **not real LLM agents** (the 40-task model benchmark needs your model keys and was not run).

## What I would do differently
Have someone else write the held-out set and the round-3 fuzzer operators, run the stack benchmark with real agents (cassettes via Passk), and add a Merkle-backed audit like Ontolite's.

## Configuration
Copy `.env.example` to `.env` (git-ignored). `TOOLPIN_APPROVAL_SECRET` and `TOOLPIN_IFC_SECRET` have no defaults.

## AI assistance
Written with Claude Code; every claim above links to a test, a generated file or a committed measurement. MIT licensed. See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [CHANGELOG](CHANGELOG.md).

## The stack
Three independent, MIT-licensed repositories that answer one question: *how do you let an agent touch real data and take real actions, and prove it behaves?*

| Repo | Role |
| --- | --- |
| [**ontolite**](https://github.com/sainikethkosaraju/ontolite) | the governed data layer: typed objects, staged actions, per-principal answers, tamper-evident audit |
| [**toolpin**](https://github.com/sainikethkosaraju/toolpin) | the trust layer between agent and tools: pinned definitions, information-flow control, approvals bound to the exact call |
| [**passk**](https://github.com/sainikethkosaraju/passk) | the measurement layer: reliability (pass^k) with honest intervals, cost per success, regression gates |
