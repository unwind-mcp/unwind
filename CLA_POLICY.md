# CLA_POLICY.md

**Status:** Draft policy for legal review  
**Project:** UNWIND  
**Last updated:** 2026-03-01 (Europe/London)

---

## 1) Purpose

UNWIND uses a Contributor License Agreement (CLA) to ensure contributions can be:

1. shipped in the open-core codebase,
2. maintained over time without licensing ambiguity,
3. commercially licensed in premium offerings without re-contacting every contributor.

This policy is designed to be transparent and contributor-friendly.

---

## 2) Open-core baseline

- Open-core code is intended to be released under **AGPL-3.0**.
- The CLA is for contributor rights management and commercial certainty.
- The CLA does **not** change the public open-core license for users.

---

## 3) Contributor rights (what contributors keep)

Contributors retain ownership of their copyright.

Contributors grant the project maintainers a broad license to use submitted code in:
- AGPL-licensed open-core releases,
- commercial/premium distributions,
- future re-licensing scenarios if required.

Contributors should be credited in normal project history (git, changelog, acknowledgements as applicable).

---

## 4) Project rights required in the CLA

The CLA should grant maintainers rights to:

1. use, modify, distribute, and sublicense contributions,
2. combine contributions with proprietary modules,
3. relicense contributions as needed for project sustainability,
4. enforce project licensing against misuse when necessary.

---

## 5) Patent clause (recommended)

The CLA should include a patent license grant from contributors for their contributions,
with a standard defensive termination clause if a contributor initiates patent litigation
against the project or its users over those contributions.

---

## 6) Warranties and provenance

Contributors should confirm that, to the best of their knowledge:
- they have the right to submit the contribution,
- the contribution does not knowingly violate third-party IP rights,
- no unauthorized confidential material is included.

---

## 7) Individual vs corporate CLA

Support both:
- **ICLA** (individual contributors)
- **CCLA** (company-authorized contributors)

If someone contributes on behalf of an employer, CCLA or explicit employer authorization is required.

---

## 8) Process policy

1. First external PR requires CLA signature check.
2. CLA check is automated in CI where possible.
3. Commits from unsigned contributors are blocked from merge until CLA completion.
4. Bot/user message provides signing instructions.

---

## 9) Scope boundary

CLA applies to code/docs/tests/scripts submitted to official UNWIND repositories.
It does not claim rights over unrelated external projects.

---

## 10) Transparency commitments

UNWIND will keep these docs public and easy to find:
- `LICENSE`
- `CONTRIBUTING.md`
- `CLA.md` (actual legal text)
- `CLA_POLICY.md` (this operational summary)

Any material changes to CLA terms should be announced in release notes / repo notices.

---

## 11) Practical recommendation

- Keep CLA text concise and plain-English where possible.
- Avoid surprise terms unrelated to IP/licensing.
- Keep contributor onboarding low-friction (single-sign flow, reusable signature).

---

## 12) Legal note

This file is a **policy draft**, not legal advice.
Final CLA terms should be reviewed by qualified counsel before adoption.
