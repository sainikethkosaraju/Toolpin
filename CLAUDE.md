# Toolpin
Pin MCP tools by hash; gate calls. Python 3.11+, MIT.
## Commands
- Setup: `pip install -e .[dev]`; Test: `pytest -q`; Lint/types: `ruff check . && pyright`
- After touching `corpus/`: `toolpin corpus --out corpus/RESULTS.md` (a test fails if it is stale)
## Rules
- Zero spend. Secrets only from env (`.env` is git-ignored). No live model calls in tests.
- Default deny. Compare secrets with `hmac.compare_digest`. Never log raw arguments (digests only).
- Heuristics are labelled; never write "secure"/"guaranteed". README claims link to a test or corpus result.
