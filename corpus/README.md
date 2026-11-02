`dev/`: cases hardening may look at. `test/`: held out; frozen by `test/FROZEN.sha256` (checked in CI); do not tune controls against it.
Add cases freely; regenerate `RESULTS.md` with `toolpin corpus --out corpus/RESULTS.md`. Misses are welcome; hiding them is not.
