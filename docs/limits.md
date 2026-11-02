# Limits and honest numbers
* Corpus (178 dev + 108 held-out cases): [../corpus/RESULTS.md](../corpus/RESULTS.md). Structural controls (lockfile, approval, handle, identity): 0 misses and 0 false positives on this corpus, which is author-written and small. Heuristics: published misses and false positives.
* Red-team: [redteam.md](redteam.md) (baseline -> hardening -> unseen operators).
* Stack benchmark: [stack-bench.md](stack-bench.md) (10/10 applicable attacks succeed unprotected; 0/11 with Toolpin; 4/4 benign workflows complete with a human approver). Scripted attackers, author-chosen scenarios.
* Overhead (in-memory client/server, 500 calls): ungated 0.51 ms median; +0.15 ms for lockfile+policy+constraints; +0.26 ms with IFC fingerprinting and output inspection (`python bench/overhead.py`). Process and network boundaries dominate real deployments.
* Not measured: behaviour of real LLM agents against Toolpin; the 40-task agent benchmark with models (needs keys); multi-worker replay beyond the SQLite-shared test; throughput.
* Cedar adapter depends on `cedarpy` 4.x (young bindings). Parity with the YAML engine is tested on a shared set only.
