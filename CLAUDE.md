# Toolpin
Session-aware gate for MCP tool use. Python 3.11+, MIT.
## Commands
- Setup: `pip install -e .[dev]`; Test: `pytest -q`; Lint/types: `ruff check . && pyright`
- Regenerate evidence: `toolpin corpus --out corpus/RESULTS.md`; `python bench/redteam.py > docs/redteam-final.json && python bench/redteam_report.py`; `python bench/stack_bench.py --md`
## Rules
- Zero spend. Secrets only from env (`.env` is git-ignored). No live model calls in tests.
- Default deny. Compare secrets with `hmac.compare_digest`. Never log raw arguments (digests only). Never store raw private data in the IFC store.
- Held-out corpus (`corpus/test`) is frozen by `FROZEN.sha256`: never tune controls against it. New fuzzer operators are "unseen" exactly once; record the first run before fixing.
- Heuristics are labelled; never write "secure"/"guaranteed". README claims link to a test or generated file.
