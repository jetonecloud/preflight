# Running Preflight from a checkout

Everything you need to build, run and poke at Preflight locally. For the
rules a change has to follow, see [`CONTRIBUTING.md`](../CONTRIBUTING.md);
for what the checks actually do, see
[`cost-check.md`](cost-check.md), [`observability.md`](observability.md)
and [`security.md`](security.md); for comparing scans, [`compare.md`](compare.md).

## Setup, once

Preflight needs Python 3.11+. Your system Python is probably older, so let
[`uv`](https://docs.astral.sh/uv/) manage both the interpreter and the
virtualenv rather than fighting it:

```sh
git clone https://github.com/jetonecloud/preflight.git
cd preflight

export PATH="$HOME/.local/bin:$PATH"   # where the uv installer puts it
uv sync --extra dev                    # .venv with a supported python + dev deps
```

Every command below assumes `uv run`, which uses that virtualenv. A bare
`PYTHONPATH=src python3 -m preflight.cli ...` still works for the
role-generation commands, but not for anything that touches boto3 — that
isn't installed for a system Python.

## See a report without an AWS account

`demo` runs the real checks against a made-up account. No credentials, no
API calls, and it exercises the same code path a real scan does.

```sh
uv run preflight demo            # prints the report, writes the JSON export
uv run preflight demo --no-json  # just the terminal copy
uv run preflight demo --out ./samples
```

In a real terminal the report is paged a section at a time; arrows move,
Enter goes forward, `a` prints all of it, `q` leaves. Redirect or pipe it
and every section is printed in order instead, which is also what the tests
see:

```sh
uv run preflight demo --no-json 2>&1 | less
```

## Compare two scans

`diff` reads two exports back, so two demo runs are enough to try it —
though with nothing changed in between, it'll say so:

```sh
uv run preflight demo --terminal --out ./samples
uv run preflight demo --terminal --out ./samples
uv run preflight diff --in ./samples
```

## Generate the read-only role

Runs entirely offline — no credentials, no AWS calls. It writes a
CloudFormation template granting only the actions the chosen modules
declare.

```sh
uv run preflight scan                          # interactive: modules, then permissions
uv run preflight scan --modules cost --save    # straight to ./preflight-role.cfn.yaml
uv run preflight scan -m cost --print > role.yaml
uv run preflight scan --list-modules
uv run preflight scan --list-checks            # each check, and the permissions it needs
```

## Scan an account

Deploy the template first (see [`installation.md`](installation.md)), then
point Preflight at the role it created:

```sh
uv run preflight scan --role-arn arn:aws:iam::<account>:role/PreflightReadOnlyRole
```

Or skip the role and use credentials you already have:

```sh
uv run preflight scan --profile my-profile
uv run preflight scan --current   # CloudShell, env vars, an instance role
```

It prints every API call it's about to make and asks before making any of
them.

| Flag | What it does |
|---|---|
| `--region us-east-1,eu-west-1` | Narrow the scan. Default: every region the account has enabled |
| `--days 30` | Usage window for the idle checks (default 14) |
| `--only unattached-ebs-volumes` | One check at a time. See `--list-checks` |
| `--redact` | Pseudonymise account and resource identifiers |
| `--out ./audits` | Where the JSON export goes |
| `--no-json` | Print the report without writing the export |
| `--yes` | Don't ask before reading the account |

## Smoke-test the scan path without AWS

Drives the whole CLI — options, confirmation, scan runner, report — against
the demo account instead of a real one, by replacing the single seam
everything goes through:

```sh
uv run python -c "
import datetime, sys
from typer.testing import CliRunner
from preflight import demo
from preflight.core import session as sm
from preflight.cli import app
sm.open_session = lambda **k: demo.DemoSession(datetime.datetime.now(datetime.UTC))
r = CliRunner().invoke(app, ['scan','--current','--yes'])
sys.stdout.write(r.stderr); print('exit', r.exit_code)
"
```

`CliRunner` isn't a terminal, so this prints the report straight through
rather than paging it. To exercise the pager itself, run `preflight demo`
in a real terminal.

## Tests and lint

```sh
uv run pytest -q
uv run pytest -q --cov=preflight --cov-report=term-missing
uv run pytest tests/test_cost_network.py -q      # one file
uv run ruff check . && uv run ruff format .
```

CI runs the same lint and tests, plus a check that
[`iam/policy.json`](../iam/policy.json) contains nothing but
`Get*`/`List*`/`Describe*`.

## Where things are

| Path | What's in it |
|---|---|
| [`src/preflight/modules/cost/`](../src/preflight/modules/cost/) | The nine cost checks, grouped by what they read: `storage`, `network`, `compute`, `database` |
| [`src/preflight/modules/observability/`](../src/preflight/modules/observability/) | The three observability checks: `alarms` and `logs` |
| [`src/preflight/modules/security/`](../src/preflight/modules/security/) | The six security checks: `identity` (root, users, keys), `network`, `storage` and `trail` |
| [`src/preflight/modules/base.py`](../src/preflight/modules/base.py) | What a `Module` and a `Check` are |
| [`src/preflight/core/pricing.py`](../src/preflight/core/pricing.py) | The price table — **re-check against AWS before a release** |
| [`src/preflight/core/scan.py`](../src/preflight/core/scan.py) | The runner, and the guard that refuses any call a check didn't declare |
| [`src/preflight/core/findings.py`](../src/preflight/core/findings.py) | `Finding`, `Severity`, `Confidence`, `Estimate` |
| [`src/preflight/core/report.py`](../src/preflight/core/report.py) | `ScanResult` and the JSON schema |
| [`src/preflight/core/compare.py`](../src/preflight/core/compare.py) | Reading exports back, and matching two scans for `preflight diff` |
| [`src/preflight/ui.py`](../src/preflight/ui.py) | Everything printed: the pickers, and the report and its pager |
| [`src/preflight/core/paper.py`](../src/preflight/core/paper.py) | The same report, laid out on pages, for the PDF |
| [`src/preflight/core/pdf.py`](../src/preflight/core/pdf.py) | The PDF writer: text, rules, tables, images, and the object graph. No dependencies |
| [`src/preflight/core/brand.py`](../src/preflight/core/brand.py) | Who made it, and the mark the PDF draws |
| [`src/preflight/assets/`](../src/preflight/assets/) | `jet1-mark.png` — add new asset files to `--add-data` in `release.yml` too |
| [`src/preflight/templates/`](../src/preflight/templates/) | `role.cfn.yaml.j2`, the generated IAM role |
| [`src/preflight/demo.py`](../src/preflight/demo.py) | The sample account |
| [`Dockerfile`](../Dockerfile) | The container image: the wheel in a venv, running as uid 1000 |
| [`packaging/homebrew/`](../packaging/homebrew/) | The formula template and the script that renders it for a release |
| [`docs/cost-check.md`](cost-check.md) | Full reference: thresholds, guards, methodology |
| [`docs/observability.md`](observability.md) | The same for the Observability Check |
| [`docs/security.md`](security.md) | The same for the Security Check |
| [`docs/release.md`](release.md) | How a tag becomes binaries, a wheel, an image and a formula |
