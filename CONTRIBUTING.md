# Contributing to UNWIND

Thanks for contributing.

UNWIND is security-critical software. Please keep contributions reproducible, test-backed, and threat-model aware.

---

## 1) Ground rules

1. **Security semantics first**: do not weaken fail-closed behavior without explicit rationale and tests.
2. **Deterministic enforcement path**: no LLM dependency in hot enforcement logic.
3. **Evidence required**: include tests and concise security reasoning for behavior changes.
4. **No secret material**: never commit secrets, tokens, private keys, or personal credentials.

---

## 2) Getting started

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

Adapter tests (Node):

```bash
cd openclaw-adapter
npm install
npm test
```

---

## 3) Contribution scope

Areas welcome for external contribution:

- enforcement hardening and tests
- canary contract coverage
- docs/spec clarity
- compatibility fixes and bug reports with repro
- Cadence core improvements (open interface layer)

Areas that may require maintainer coordination first:

- policy-order changes in `unwind/enforcement/pipeline.py`
- CRAFT verifier/provenance format changes
- sidecar request/response contract changes
- licensing/governance docs

---

## 4) Pull request process and checklist

1. **One PR = one intent.** A bug fix is one PR. A refactor is separate. Do not mix refactoring with feature/fix changes.
2. **Tests required.** Every bug fix needs a regression test. New features need coverage.
3. **Run tests before submitting:**
   ```bash
   python -m pytest --tb=short -q
   ```

Before opening a PR, ensure:

- [ ] tests pass locally (`pytest -q`)
- [ ] new behavior has tests (or test updates) explaining intent
- [ ] docs updated when changing user-visible behavior
- [ ] no unrelated formatting churn
- [ ] commit messages are clear and scoped

For security-impacting PRs, include:

- threat model impact (what attack path changes)
- fail-open/fail-closed analysis
- rollback or mitigation notes

### Tier A invariant checklist (required for Tier A changes)

Tier A = enforcement pipeline, CRAFT, Ghost Mode, sidecar.

- [ ] Fail-closed preserved
- [ ] Path jail intact
- [ ] Ghost Mode isolation intact
- [ ] CRAFT chain integrity intact
- [ ] Rollback capability intact

---

## 5) Code style

- Follow existing patterns in the codebase
- No formal linter enforced yet (planned for CI)
- Keep it simple; avoid unnecessary complexity

---

## 6) Issue labels

- `bug` — something is broken
- `enhancement` — feature/improvement request
- `security` — security-related issue (use private path for vulnerabilities)
- `documentation` — docs improvement

---

## 7) CLA requirement

UNWIND requires a signed CLA for external contributions.

- Policy: `CLA_POLICY.md`
- Draft agreement text: `CLA.md`

PRs from unsigned contributors may be blocked until CLA completion.

---

## 8) Licensing

Open-core licensing direction is AGPL-3.0 (see repository `LICENSE`).

By submitting a pull request, you agree your contributions are licensed under project terms.

---

## 9) Reporting vulnerabilities

Please do not open exploit details publicly first.

Report vulnerabilities using the process in `SECURITY.md`.

If a secure channel is temporarily unavailable, contact maintainers directly for coordinated disclosure.

---

## 10) Communication style

- Keep reports concise and technical.
- Distinguish facts from assumptions.
- Provide repro steps and exact versions/commits.

---

## 11) Maintainer notes

Maintainers may decline contributions that:

- reduce security posture without acceptable tradeoff,
- create legal/licensing ambiguity,
- lack reproducible tests for critical behavior changes.
