# Changelog
## 0.2.0
- **Information-flow control** (lethal-trifecta rule + value-level taint with encoded-copy and figure matching) and **result inspection** (secret redaction, injection annotate/block, dynamic untrusted labelling).
- **Proxy mode** (`toolpin run`) with sandboxed spawn and logged launches; config file loader.
- **Durable nonces** (SQLite, multi-process) and **key rotation** for approvals; **Ed25519-signed, policy-pinned lockfile**; **JWKS** RS256/ES256 identity with RFC 9728/8707 plumbing.
- **Red-team methodology**: held-out corpus frozen by hash, mutation fuzzer, baseline recorded before hardening, normalisation pipeline, unseen-operator round that measured overfitting.
- **Stack benchmark** against Ontolite; it found and fixed a short-figure exfiltration hole.
- Landscape teardown: pinning lockfiles already exist; positioning corrected.
## 0.1.0
Lockfile, heuristic scan, YAML/Cedar/OPA policy, call-bound approvals, constraints, budgets, audit, identity helpers, library middleware, first corpus. Proxy modes were cut.
