# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-03

The release where `scan` actually scans. 0.1.0 could generate the role; this one reads the account with it, reports what it found, and writes that report where you want it.

### Added
- **The Cost Check runs.** `preflight scan --role-arn <arn>` (or `--profile`, or `--current` for CloudShell and ambient credentials) reads the account and reports on it. Nine checks: unattached EBS volumes, Elastic IPs attached to nothing, idle NAT gateways, load balancers with nothing behind them, instances stopped for a month or more, stopped RDS instances, snapshots nothing is using, old manual database snapshots, and instances bigger than their workload. See [`docs/cost-check.md`](docs/cost-check.md).
  - Scans every region the account has enabled by default; `--region us-east-1,eu-west-1` narrows it.
  - Before reading anything, prints every call it's about to make — including the region, pricing and tag reads no single check owns — and asks. `--yes` skips the question; without a terminal it says it's going ahead rather than hanging.
  - Each finding carries its own arithmetic. Estimates use us-east-1 list prices (the lowest AWS charges), discount snapshots for being incremental, and model no Savings Plans or Reserved Instances. A figure that can't be known is omitted rather than guessed.
  - Guards against false positives throughout: volumes detached this week, snapshots an AMI depends on, instances with one busy hour a day, network-heavy boxes with quiet CPUs, spot and dedicated capacity, automated RDS snapshots, and anything younger than the metric window. An empty CloudWatch series is treated as "we don't know", never as zero.
  - `preflight:ignore` on a resource silences it everywhere. Set the value to `false` to switch the tag off without removing it.
  - `--only <check>`, `--days N`, `--out <dir>`, `--no-json`, and `--list-checks`.
- **The report is the terminal.** It opens with three lines — what was found, where the JSON went, how to move — and then shows itself a section at a time: the estimated monthly saving, the three things worth doing first, an index of every finding, each check's findings with their evidence and derivation, what was checked, what the scan couldn't read and why, and how the numbers were worked out. Plain ASCII tables throughout. Nothing to open, nothing to fetch.
  - Arrow keys move between sections, Enter goes forward, `a` prints the whole report at once, `q` leaves. A section taller than the window is measured and split rather than scrolled off the top.
  - Without a terminal to read keypresses from — a pipe, CI, a log — every section is printed in order instead, so nothing is hidden from a script.
- **The report as a PDF**, for when the person who needs to read it isn't the person who ran the scan. The same sections off the same `ScanResult`, paginated, with a contents page, a footer naming the account on every page, and every finding printed in full with its evidence and derivation — nothing behind a keypress, because paper hasn't got any. Set in Helvetica, with ruled tables, one teal accent for headings, three colours for severity, and nothing set in capitals: a document to be read and printed, not a dashboard. Colour is always the second signal — every coloured word is written out — so the report means the same thing in greyscale.
  - Preflight writes the PDF itself: no rendering engine, no browser, no system libraries, and no new dependency. It asks for the base fonts every reader already has, so there are no scripts, no links out, and nothing fetched when the file is opened. Content streams are left uncompressed so the file can be read with `strings`.
  - The Jet1 mark on the cover and in the colophon is the one image, and it ships inside Preflight. A plain PNG's pixel data is already in the one compressed form a PDF understands — PNG's scanline filtering is PDF's predictor 15 — so it's copied in rather than decoded, which is what keeps the writer dependency-free.
  - The report says who made it: what Preflight is, who Jet1 are, and where to find both, for a reader who never ran the tool.
  - The same scan always produces the same bytes — the creation date comes from the scan, not the clock.
- **A choice of where the report goes.** An interactive scan asks two questions before it reads anything: the terminal or a PDF, and then whether to keep the JSON export. The first is an arrow-key choice — Up/Down to move, Enter to choose — redrawn in place so the scan plan above it stays on screen. `--pdf`, `--terminal` and `--no-json` each answer one of them and skip it. Both questions are settled before the account is read, so a scan nobody is watching still finishes by writing its files. Where there's nobody to ask — a pipe, CI, `--yes` — the defaults are unchanged: the terminal report and the JSON.
- **A versioned JSON export** (`schema_version: 1`) written alongside the printed report, with stable finding IDs so two scans can be diffed to see what actually got fixed. `--no-json` leaves the terminal copy as the only output.
- **`--redact`** replaces account and resource identifiers with stable pseudonyms — the same volume is `vol-1` throughout — leaving the findings, numbers and reasoning intact.
- **`preflight demo`** renders a sample report by running the real checks against a made-up account, so what it shows is what the tool does, including the cases the guards correctly decline. No AWS calls, no credentials.
- **Last month's bill as context**, via `ce:GetCostAndUsage`, so the report can say "about 11% of your bill" instead of leaving you to work out whether $530 matters. Optional: denied means the comparison is left out.
- **Checks can only make the calls they declare.** `ScanContext` refuses any action outside the running check's declaration, and a test asserts a module's `iam_actions` is exactly the union of its checks' actions and its support actions. The role you read before deploying is now provably the complete set of calls Preflight can make.
- **Gaps are reported, never papered over.** A check denied a permission is marked skipped with the action named, in the terminal and in the report, alongside the command to regenerate a complete role. A region that won't answer is noted and the scan carries on.
- **Homebrew and Docker, which the docs already promised.** `brew install jetonecloud/tap/preflight` installs the same prebuilt binary the installer downloads, checksum and all — the formula is rendered from a template in this repo and committed to the tap by the release, so the version, the four asset URLs and their checksums can't drift from what actually shipped. `docker run ghcr.io/jetonecloud/preflight` runs the wheel in a slim Python image, as uid 1000 rather than root, with `preflight` as the entrypoint and `/out` as the working directory, so `-v "$PWD:/out"` leaves the report in the directory you ran it from. Built for amd64 and arm64, tagged with the version, the minor series and `latest`, and attested like the binaries. See [`docs/installation.md`](docs/installation.md), and [`docs/release.md`](docs/release.md) for the one-time tap and registry setup.
- Docs: [`docs/cost-check.md`](docs/cost-check.md), [`docs/installation.md`](docs/installation.md) and [`docs/cloudshell.md`](docs/cloudshell.md) — the last two were linked from the README but didn't exist.

### Changed
- `preflight scan --list-checks` is the finer-grained companion to `--list-modules`: it prints each check and the exact permissions it needs.
- The `cost` module is now a package (`modules/cost/`) grouped by what each check reads. `from preflight.modules.cost import COST` is unchanged.
- The finding schema in `CONTRIBUTING.md` now matches the code: dollar fields carry their currency (`estimated_monthly_savings_usd`), and the derivation is a first-class field rather than a line of evidence.
- Tested on Python 3.11 through 3.14, and the classifiers say so.

### Fixed
- `SECURITY.md` claimed Preflight checks the permissions of the identity it runs as. It can't — that needs `iam:SimulatePrincipalPolicy`, which it deliberately doesn't ask for. It now describes what the identity's ARN alone can tell you, which is what the code does.
- `README.md` and `SECURITY.md` described opt-in email delivery and `preflight preview` as though they worked. Both are marked as planned; `preflight preview` is still a stub.
- Old manual RDS snapshots: the check now re-checks `SnapshotType` on each snapshot rather than trusting the request filter, so automated backups can't be reported as waste if the filter ever fails to apply.

### Notes
- Dollar figures come from a hard-coded table of us-east-1 list prices in `core/pricing.py`, carrying the date it was last reviewed, plus `pricing:GetProducts` for instance rates. **Re-check the table against AWS's pricing pages before cutting a release.**
- The Homebrew tap isn't published yet: the formula and its renderer ship in this repo, but the release skips the tap until it's configured. `brew install jetonecloud/tap/preflight` doesn't work for this version — use the installer, `pipx`, `uv` or Docker.

## [0.1.0] - 2026-10-04

The permissions, first. Everything needed to generate and read the read-only role, with no check wired up to use it yet.

### Added
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

### Fixed
- Repository links pointed at a `jet1-cloud/preflight` that doesn't exist; they're `jetonecloud/preflight` now.
- `SECURITY.md` described a `.sig`/`.sha256` verification flow and a `docs/verifying-releases.md` that didn't exist. It now documents the checksum and `gh attestation verify` steps the release pipeline actually produces.

### Notes
- The checks themselves aren't wired up yet, so `--profile`, `--region` and `--role-arn` are accepted but inert. This release gets the permissions in place first.
