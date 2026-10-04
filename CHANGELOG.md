# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
