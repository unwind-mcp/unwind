# Contributing to UNWIND

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js (for the OpenClaw adapter)

### Setup
```bash
git clone https://github.com/brugai/unwind.git
cd unwind
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

## Pull Request Process

1. **One PR = one intent.** A bug fix is one PR. A refactor is a separate PR. Never mix refactoring with feature/fix changes.
2. **Tests required.** Every bug fix needs a regression test. New features need coverage.
3. **Run tests before submitting:**
   ```bash
   python -m pytest --tb=short -q
   ```
4. **Tier A changes** (enforcement pipeline, CRAFT, Ghost Mode, sidecar) must include the invariant checklist in the commit message:
   - Fail-closed preserved
   - Path jail intact
   - Ghost Mode isolation intact
   - CRAFT chain integrity intact
   - Rollback capability intact

## Code Style

- Follow existing patterns in the codebase
- No formal linter enforced yet (planned for CI)
- Keep it simple — avoid over-engineering

## Issue Labels

- `bug` — Something is broken
- `enhancement` — New feature or improvement
- `security` — Security-related issue (use private reporting for vulnerabilities)
- `documentation` — Docs improvement

## License

By submitting a pull request, you agree that your contributions are licensed under the [AGPL-3.0-or-later](LICENSE).
