# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **The Cost Check runs.** `preflight scan --role-arn <arn>` (or `--profile`, or `--current` for CloudShell and ambient credentials) reads the account and writes a report. Nine checks: unattached EBS volumes, Elastic IPs attached to nothing, idle NAT gateways, load balancers with nothing behind them, instances stopped for a month or more, stopped RDS instances, snapshots nothing is using, old manual database snapshots, and instances bigger than their workload. See [`docs/cost-check.md`](docs/cost-check.md).
  - Scans every region the account has enabled by default; `--region us-east-1,eu-west-1` narrows it.
  - Before reading anything, prints every call it's about to make — including the region, pricing and tag reads no single check owns — and asks. `--yes` skips the question; without a terminal it says it's going ahead rather than hanging.
  - Each finding carries its own arithmetic. Estimates use us-east-1 list prices (the lowest AWS charges), discount snapshots for being incremental, and model no Savings Plans or Reserved Instances. A figure that can't be known is omitted rather than guessed.
  - Guards against false positives throughout: volumes detached this week, snapshots an AMI depends on, instances with one busy hour a day, network-heavy boxes with quiet CPUs, spot and dedicated capacity, automated RDS snapshots, and anything younger than the metric window. An empty CloudWatch series is treated as "we don't know", never as zero.
  - `preflight:ignore` on a resource silences it everywhere. Set the value to `false` to switch the tag off without removing it.
  - `--only <check>`, `--days N`, `--format html,json`, `--out <dir>`, `--open`, and `--list-checks`.
- **A report worth sending to someone.** A self-contained HTML file — no fonts, scripts or images to fetch — leading with the estimated monthly saving, the three things worth doing first, and every finding's evidence and derivation. It ends with what the scan couldn't read and why. Prints to PDF from a browser.
- **A versioned JSON export** (`schema_version: 1`) alongside it, with stable finding IDs so two scans can be diffed to see what actually got fixed.
- **`--redact`** replaces account and resource identifiers with stable pseudonyms — the same volume is `vol-1` throughout — leaving the findings, numbers and reasoning intact.
- **`preflight demo`** renders a sample report by running the real checks against a made-up account, so what it shows is what the tool does, including the cases the guards correctly decline. No AWS calls, no credentials.
- **Last month's bill as context**, via `ce:GetCostAndUsage`, so the report can say "about 11% of your bill" instead of leaving you to work out whether $530 matters. Optional: denied means the comparison is left out.
- **Checks can only make the calls they declare.** `ScanContext` refuses any action outside the running check's declaration, and a test asserts a module's `iam_actions` is exactly the union of its checks' actions and its support actions. The role you read before deploying is now provably the complete set of calls Preflight can make.
- **Gaps are reported, never papered over.** A check denied a permission is marked skipped with the action named, in the terminal and in the report, alongside the command to regenerate a complete role. A region that won't answer is noted and the scan carries on.
- Docs: [`docs/cost-check.md`](docs/cost-check.md), [`docs/installation.md`](docs/installation.md) and [`docs/cloudshell.md`](docs/cloudshell.md) — the last two were linked from the README but didn't exist.
- `preflight scan` first slice: pick modules, then generate the read-only CloudFormation role those modules need. Runs entirely offline — no AWS calls, no credentials.
  - Interactive picker listing every module, with Cost Check selectable and the rest marked as coming soon.
  - A second picker for the permissions themselves: every AWS service the selected modules need starts checked, and you can switch off the ones you'd rather not grant. Up/Down to move, Enter to check or uncheck, `a` for all and `n` for none, then Enter on the Continue row. Where keypresses can't be read one at a time — a pipe, CI — the same picker takes typed answers instead. `sts:GetCallerIdentity` is always included. Non-interactively that's `--services ec2,rds`.
  - One step to a screen: each step clears the last and keeps the wordmark, and step 3 just asks where to save — press Enter for the directory you ran the command from.
  - `--modules cost --save` for non-interactive use, plus `--services`, `--print`, `--out`, `--force` and `--list-modules`.
  - Generated templates are deterministic, carry the command that reproduces them (including any service narrowing), and name only the actions the selected modules declare.
- Module registry (`preflight.modules`) where each module declares the IAM actions its checks call. The union of all modules matches `iam/policy.json`, which a test enforces.
- Generation-time read-only guard (`preflight.core.iam`): a module that declares a write or wildcard action fails the build rather than ending up in a deployed role.
- `preflight --version`, on stdout, so scripts (including the installer) can read it.
- Release pipeline: tagging `v*` reruns CI, checks the tag against `preflight.__version__`, builds a single-file binary per platform with PyInstaller, smoke-tests each one by generating a role template with it, then publishes the binaries, `checksums.txt`, a signed build provenance attestation, and `install.sh` to GitHub Releases — plus the sdist and wheel to PyPI via trusted publishing. See [`docs/release.md`](docs/release.md).
- `install.sh`: detects platform, downloads from the latest release, verifies the SHA-256 against `checksums.txt` and refuses to install on a mismatch. Honours `PREFLIGHT_VERSION` and `PREFLIGHT_BIN`. This is what `curl -fsSL https://jetonecloud.com/preflight | sh` serves.
- Project scaffolding: license, contribution guidelines, security policy, issue/PR templates, CI workflow.

### Changed
- `preflight scan --list-checks` is the finer-grained companion to `--list-modules`: it prints each check and the exact permissions it needs.
- The `cost` module is now a package (`modules/cost/`) grouped by what each check reads. `from preflight.modules.cost import COST` is unchanged.
- The finding schema in `CONTRIBUTING.md` now matches the code: dollar fields carry their currency (`estimated_monthly_savings_usd`), and the derivation is a first-class field rather than a line of evidence.

### Fixed
- Repository links pointed at a `jet1-cloud/preflight` that doesn't exist; they're `jetonecloud/preflight` now.
- `SECURITY.md` described a `.sig`/`.sha256` verification flow and a `docs/verifying-releases.md` that didn't exist. It now documents the checksum and `gh attestation verify` steps the release pipeline actually produces.
- `SECURITY.md` claimed Preflight checks the permissions of the identity it runs as. It can't — that needs `iam:SimulatePrincipalPolicy`, which it deliberately doesn't ask for. It now describes what the identity's ARN alone can tell you, which is what the code does.
- `README.md` and `SECURITY.md` described opt-in email delivery and `preflight preview` as though they worked. Both are marked as planned; `preflight preview` is still a stub.
- Old manual RDS snapshots: the check now re-checks `SnapshotType` on each snapshot rather than trusting the request filter, so automated backups can't be reported as waste if the filter ever fails to apply.

### Notes
- Dollar figures come from a hard-coded table of us-east-1 list prices in `core/pricing.py`, carrying the date it was last reviewed, plus `pricing:GetProducts` for instance rates. **Re-check the table against AWS's pricing pages before cutting a release.**
