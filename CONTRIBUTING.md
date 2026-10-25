# Contributing to Preflight

Thanks for considering a contribution. Preflight is Apache-2.0 licensed and built in the open — see [`README.md`](README.md) for what it does and [`docs/cost-check.md`](docs/cost-check.md) for how a module is put together.

## Ground rules

1. **Read-only, no exceptions.** Any code that calls a write/mutating AWS API will be rejected. Every new API call must be added to the relevant module's declared permissions and to [`iam/policy.json`](iam/policy.json), with only the minimal `Get*`/`List*`/`Describe*` action needed.
2. **Never log or transmit credentials, secrets, or raw API responses.** Findings must be derived/minimized before they leave a module.
3. **License hygiene.** Do not copy GPL/AGPL-licensed code into this repo. If you're porting check logic from another open-source project, confirm its license is compatible (Apache-2.0/MIT with attribution) and add the attribution to [`NOTICE`](NOTICE).
4. **Avoid false positives over false negatives.** If a check can't confidently tell whether something is a real problem (e.g., "idle" without checking tags/recent activity), don't flag it, or lower its confidence and say why.
5. **Plain language.** Findings and recommendations should read like something you'd say to a startup CTO on a call, not a raw API dump.

## Development setup

```sh
git clone https://github.com/jetonecloud/preflight.git
cd preflight
uv sync
uv run pytest
```

- Python 3.11+, managed via `uv` and `pyproject.toml`.
- Lint/format with **Ruff**: `uv run ruff check . && uv run ruff format .`
- Tests with **pytest** + **moto** for AWS mocking: `uv run pytest`

## Adding or changing a check

Each module is a self-contained plugin under `modules/`; shared logic belongs in `core/`. A module with more than a couple of checks is a package — see [`modules/cost/`](src/preflight/modules/cost/), where the checks are grouped by what they read (`storage.py`, `network.py`, `compute.py`, `database.py`) and `__init__.py` holds the declaration.

A check is a `Check` (see [`modules/base.py`](src/preflight/modules/base.py)) with a key, a title, a one-line `looks_for` written in plain words, the IAM actions it needs, and a function taking a `ScanContext` and yielding `Finding`s.

- **Declare every action the check calls.** This is enforced at runtime, not by review: `ScanContext` raises `UndeclaredAction` if a check reaches for anything outside its own list. A test also asserts that a module's `iam_actions` is exactly the union of its checks' actions plus its `support_actions`, so the generated role can't drift from the code. Update `iam/policy.json` and `SECURITY.md` if the set of data read changes.
- **Every finding uses the shared schema** in [`core/findings.py`](src/preflight/core/findings.py): `check`, `module`, `title`, `severity`, `confidence`, `resource`, `evidence`, `recommendation`, and an optional `estimate` (which serialises as `estimated_monthly_savings_usd`, `estimated_annual_savings_usd` and `estimate_basis`). Severity defaults to what the finding costs; set it explicitly only when the money understates the problem.
- **Add tests for every new check**, including at least:
  - A case with no finding (the check correctly stays quiet)
  - A false-positive guard case (e.g., a resource that looks idle but is tagged or recently active)
  - A missing-permission case, asserting the check is skipped and names the action

  [`tests/conftest.py`](tests/conftest.py) has the stubs; a check test should be a short list of API responses and an assertion.
- **If the check estimates dollar savings**, keep the estimate conservative and put the derivation in `Estimate.basis` as a sentence someone can check with a calculator. A figure that can't be known is `None` — never a plausible-looking guess.
- **Respect the opt-out.** Resources tagged `preflight:ignore` are skipped; use `core.scan.ignored()`.
- **Treat an empty CloudWatch series as "we don't know", not as zero.** It's the easiest way to invent a false positive.

## Commit messages

This repo uses [Conventional Commits](https://www.conventionalcommits.org/): `<type>: <summary>`, optionally followed by a body explaining why.

Common types: `feat`, `fix`, `docs`, `chore`, `ci`, `test`, `refactor`.

```
chore: scaffold enterprise repo structure

Add README, contribution/security/conduct docs, GitHub issue/PR
templates, CI workflow with a read-only IAM policy check, pyproject
packaging, a minimal CLI skeleton, and the baseline read-only IAM
policy and role template.
```

Prefer one commit per logical change where practical, but a single well-described commit is fine for a batch of related scaffolding/setup work.

## Pull requests

1. Open an issue first for anything beyond a small fix, so we can discuss approach before you invest time.
2. Keep PRs focused — one module/feature/fix per PR.
3. Include tests. CI (lint + tests) must pass.
4. Describe what the change reads from AWS and why, so reviewers can verify it stays read-only.
5. By submitting a PR, you agree your contribution is licensed under Apache-2.0.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating in issues, PRs, or discussions.

## Reporting bugs vs. security issues

- Functional bugs: open a GitHub issue using the bug report template.
- Security vulnerabilities (especially anything that writes to AWS, leaks credentials, or transmits data without consent): follow [`SECURITY.md`](SECURITY.md) instead — do not open a public issue.
