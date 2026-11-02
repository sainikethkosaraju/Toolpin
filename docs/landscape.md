# Landscape teardown (blueprint task T0.3)
Method: one web-search session on 2026-11-02. These are **leads, not audited conclusions**; verify before publishing any comparison. No claim here is endorsed by, or compatible with, any listed project.

| Capability | Already exists (per search) | Status of the blueprint's "gap" |
| --- | --- | --- |
| Tool-definition **pinning / lockfile** to catch rug pulls | [`mcp-pin`](https://pypi.org/project/mcp-pin/0.1.8/) (committed lockfile, blocks mismatches), [`heldfast`](https://pypi.org/project/heldfast/) (lockfile + public log of seen tools), [`mcp-warden`](https://pypi.org/project/mcp-warden-cli/) (signed `warden.lock`, CI drift check), [`vex-mcp`](https://pypi.org/project/vex-mcp/0.2.1/) (stdio gateway: description scan + pinning + default-deny) | **CLOSED.** A lockfile alone is table stakes. Toolpin has one (signed, policy-pinned) but does not claim it as the differentiator. |
| Static scan of tool descriptions | `vex-mcp`, MCP-security scanners mentioned in the same results | **Closed as a differentiator.** Toolpin's scanner is a labelled heuristic with a measured red-team report. |
| Default-deny policy at a gateway | `vex-mcp`; vendor gateways ([Zuplo notes](https://zuplo.com/blog/remote-mcp-server-rug-pull/) that automatic definition pinning is not something its gateway does today) | Overlap. |
| Call-bound human approval **over MCP MRTR (2026-07-28)** with an HMAC token bound to principal+tool+canonical arguments, single-use nonces in a durable store | not found in this search | **Plausibly open**, unverified. |
| **Information-flow control** across a session (lethal-trifecta rule + value-level taint with encoded-copy detection) | not found in this search | **Plausibly open**, unverified. This is the main differentiator. |
| Measured, published attack corpus with a held-out split and an **unseen-operator** overfitting measurement | not found | Plausibly open; my own corpus is author-written (see red-team report). |

**Positioning after the teardown:** Toolpin is *not* "the lockfile for MCP". It is the session-aware gate: information-flow control, call-bound approvals, sandboxed proxying, and evidence-first reporting of what its heuristics miss. If a reviewer asks "why not mcp-pin?", the answer is: use it for pinning; Toolpin's value is what happens *between* calls.
