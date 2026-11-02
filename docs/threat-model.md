# Threat model
**Assets:** the user's data and the actions reachable through MCP tools. **Adversaries:** a malicious or compromised MCP server (poisoned/changed tools, injected results), a prompt-injected agent, a malicious client, a network attacker.

| Threat | Control | Evidence |
| --- | --- | --- |
| Rug pull / tool poisoning at lock time | canonical-hash lockfile (optionally Ed25519-signed, policy-pinned); lock-time scan | `tests/test_core.py`, `tests/test_hardening.py`, corpus, `tests/test_proxy.py` |
| Poisoned results (indirect injection) | output inspection (annotate/block), dynamic untrusted label | `tests/test_hardening.py` |
| Exfiltration by a prompt-injected agent | IFC trifecta + value-flow rules; approvals | `tests/test_ifc.py`, [stack-bench.md](stack-bench.md) |
| Secrets in tool output | redaction before the model sees them | `tests/test_hardening.py` |
| SSRF / path traversal / injection in arguments | canonicalising constraints (heuristic where noted) | corpus, [redteam.md](redteam.md) |
| Approval forgery / replay / tampering / expiry | HMAC token over principal+tool+args hash+nonce+expiry+kid; durable single-use nonces; key rotation | `tests/test_core.py`, `tests/test_hardening.py` (24 concurrent redemptions: exactly 1 wins) |
| Confused deputy / wrong audience | JWKS (RS256/ES256) verification with an algorithm allow-list, audience = this resource (RFC 8707), RFC 9728 metadata | `tests/test_hardening.py` |
| Malicious upstream process | sandboxed spawn (env, rlimits, no_new_privs, bwrap optional) | `tests/test_proxy.py` |
| Lying about what happened | hash-chained audit of digests, optional Ed25519 | `tests/test_core.py` |

## NOT covered (read this)
- **A server that is malicious at lock time and never changes** passes the lockfile; only review, the scanner (heuristic) and IFC/approvals limit the damage.
- **Heuristics miss things**: see [redteam.md](redteam.md). Round-2 operators initially evaded 7-71% of the time; paraphrase and novel languages are structurally out of reach of pattern matching.
- **IFC cannot see paraphrase / lossy re-expression / covert channels**, and a private-only session can leak by paraphrase (accepted).
- **SSRF is static** unless you pass a resolver; DNS rebinding between check and fetch is possible.
- **Sandbox is not a security boundary** against a determined malicious server (use bwrap/containers).
- **The approval secret and IFC secret live in your process environment.** Anyone holding them can mint approvals / read fingerprints.
- **A human who approves blindly.** The prompt shows canonical arguments (truncated at 500 chars).
- **Audit tail truncation** is undetectable without pinning a head; the audit file is unsigned unless a key is configured, and Toolpin does not (unlike Ontolite) use a Merkle log.
- **JWKS fetching, caching and rotation** are the caller's job (`jwks` may be a callable); there is no OAuth server here.
- **Upstream elicitation** is unsupported through the proxy; HTTP-upstream proxy mode is exercised by the SDK client only (no network test in CI).
