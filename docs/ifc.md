# Information-flow control
The "lethal trifecta" is an agent that can read **private** data, ingest **untrusted** content, and communicate **externally**. No single call looks wrong, so per-call policy cannot see it. Toolpin keeps session memory:

| rule | trigger | default |
| --- | --- | --- |
| **trifecta** | an `egress` tool is called in a session that has seen private AND untrusted content | `require_approval` |
| **value flow** | an `egress` call's arguments contain data fingerprinted from a private result | `require_approval` (benchmarks use `deny`) |

Labels come from config (`ifc.tools`), plus **dynamic labelling**: a result that contains instruction-like text marks the session untrusted even if the tool was not labelled.
Fingerprints: salted HMACs of (a) identifier-like atoms, (b) figures with >= 5 significant digits (`48215.0 == 48,215`), (c) 5-word shingles; percent/base64/hex copies in arguments are decoded before matching. The store holds no raw secrets and is bounded.

**What it cannot do:** see paraphrase, summarisation, translation, spelled-out numbers, or covert channels. Those are exactly the cases the trifecta rule exists for, and the stack benchmark ([stack-bench.md](stack-bench.md)) shows each rule catching what the other misses. A session with private data and *no* untrusted content can still leak by paraphrase: that residual risk is accepted by design.
**Found by benchmarking:** the first version fingerprinted only identifier-like atoms, so a base64 copy of a short figure (`48215.0`) left in an email slipped through (`tests/test_ifc.py::test_figures_are_tracked...`).
