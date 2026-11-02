# Threat model
**Assets:** the user's data and actions reachable through MCP tools. **Adversaries:** a malicious or compromised MCP server (poisoned/changed tools), a prompt-injected agent, a malicious client, a network attacker between client and gate.

| Threat | Control | Evidence |
| --- | --- | --- |
| Tool poisoning (hidden instructions) | `scan` (heuristic) + lockfile review | corpus `tp-*` (misses published) |
| Rug pull (definition changes after approval) | lockfile hash over the full canonical definition; changed/added tools are hidden and uncallable | corpus `rp-*`, `tests/test_core.py` |
| Shadowing / name collision | exact + look-alike name check | corpus `sh-*` |
| SSRF | static URL check (stdlib `ipaddress`, handles decimal/hex/octal/short/mapped forms), optional resolver | corpus `ss-*` |
| Argument injection | path containment, injection heuristic, numeric ceilings | corpus `ai-*` |
| Confused deputy | audience-bound claims, no token passthrough, principal-bound handles | corpus `cd-*`, `hh-*` |
| Approval forgery/replay/tamper/expiry | HMAC token bound to principal+tool+canonical-args hash+nonce+expiry; nonce single-use | corpus `ap-*`, `tests/test_gate.py` |
| Unlogged actions | hash-chained audit of digests (not raw args), optional Ed25519 | `tests/test_core.py` |

## NOT covered (read this)
- **Malicious behaviour behind an unchanged definition.** The lock pins the *description*, not what the server does. A server that was malicious at lock time stays malicious.
- **Heuristic controls miss things.** `scan`, `args`, `shadow` and `policy` have published misses in [corpus/RESULTS.md](../corpus/RESULTS.md) (paraphrase, non-English, leetspeak, encoded payloads, typosquats, DNS rebinding, redirects, over-broad globs).
- **SSRF is static** unless you supply a resolver; even then DNS rebinding between check and fetch (TOCTOU) is possible. Pin the resolved address when you fetch.
- **Tool outputs** (indirect prompt injection in returned data) are not inspected; only size is capped.
- **Process compromise / secret theft.** The approval secret lives in your process environment. Anyone with it can mint approvals.
- **A human who approves blindly.** The approval message shows the canonical arguments (truncated at 500 chars).
- **Audit tail truncation** is undetectable without a pinned head hash; the audit is unsigned unless you configure a key.
- **Transport authentication**: `identity.py` validates claims you hand it; it is not an OAuth server and `verify_hs256_jwt` is a minimal shared-secret verifier.
- **Multi-worker deployments:** the nonce store is in-memory per process (and the SDK's `requestState` key is ephemeral unless configured). Replay protection across workers needs a shared store.
- **Proxy modes (stdio/HTTP) are not implemented** (cut per the blueprint's scope rule 4). Library mode wraps an official-SDK `MCPServer`.
