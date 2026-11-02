# Limits and honest numbers
* Corpus: see [corpus/RESULTS.md](../corpus/RESULTS.md). Structural controls: 0 misses, 0 false positives on this corpus (the corpus is small and written by the author; it is evidence, not proof). Heuristics: published misses and false positives.
* Overhead (in-memory MCP client/server, 500 calls, lockfile + policy + one injection check): median +0.14 ms per call (0.42 ms -> 0.55 ms), measured with `python bench/overhead.py` on the build sandbox. Network/process boundaries dominate real deployments.
* Not benchmarked: the 40-task agent benchmark with and without Toolpin (needs free-tier model keys and nightly collection; not run).
* Cedar adapter depends on `cedarpy` 4.x (young bindings). Parity with the YAML engine is tested on a shared set only.
