# AGENTS.md — palantir-object-authority-matrix

**Company:** Palantir
**Domain:** Enterprise Data Platform & Authority Governance

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/palantir_object_authority_matrix/core.py` — Domain logic (Enterprise Data Platform & Authority Governance)
- `tests/` — Verified test suite
- `.github/workflows/ci.yml` — Enforced CI pipeline
