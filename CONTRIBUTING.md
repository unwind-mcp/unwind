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

## 2) Contribution scope

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

## 3) Setup and test

From repo root:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
python -m pytest --tb=short -q
```

Adapter tests (Node):

```bash
cd openclaw-adapter
npm install
npm test
```

---

## 4) Pull request checklist

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

---

## 5) CLA requirement

UNWIND requires a signed CLA for external contributions.

- Policy: `CLA_POLICY.md`
- Draft agreement text: `CLA.md`

PRs from unsigned contributors may be blocked until CLA completion.

---

## 6) Licensing

Open-core licensing direction is AGPL-3.0 (see repository `LICENSE` once finalized).

Do not submit code you are not legally permitted to license under project terms.

---

## 7) Reporting vulnerabilities

Please do not open public exploit details first.

Use private/security contact path as documented in repo security policy (when published), or contact project maintainers directly for coordinated disclosure.

---

## 8) Communication style

- Keep reports concise and technical.
- Distinguish facts from assumptions.
- Provide repro steps and exact versions/commits.

---

## 9) Maintainer notes

Maintainers reserve the right to decline contributions that:

- reduce security posture without acceptable tradeoff,
- create legal/licensing ambiguity,
- lack reproducible tests for critical behavior changes.
