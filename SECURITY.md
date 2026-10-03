# Security Policy

Preflight is a read-only auditing tool that runs against your AWS account. Security and trust are the product — read this before running it against anything you care about.

## Threat model and guarantees

- **Read-only by construction.** The published IAM policy ([`iam/policy.json`](iam/policy.json)) contains only `Get*`, `List*`, and `Describe*` actions. There is no wildcard `*` action, and no action that creates, modifies, or deletes any AWS resource. If you find one that does, it's a bug — report it (see below).
- **Credentials never leave your machine.** Preflight uses the standard AWS SDK credential chain (environment variables, shared config/profile, SSO, instance/task role, `assume-role`). It never prompts for or accepts a pasted access key/secret, never writes credentials to disk or logs, and never transmits them anywhere.
- **Over-privileged identity warning.** Preflight checks the permissions of the identity it's running as. If that identity has write or admin access, it warns you and recommends using the dedicated read-only role in [`iam/role.cfn.yaml`](iam/role.cfn.yaml) instead.
- **Nothing leaves your machine without explicit, informed consent.** By default, Preflight only writes a local HTML and JSON report. The *only* way data leaves your machine is if you explicitly opt in to emailing yourself a copy via a Jet1-hosted endpoint, and `preflight preview` will show you the exact payload before you confirm.
- **Summaries, not raw data.** If you opt in to sending a report, Preflight sends a summary (scores, findings, optional dollar estimates) — never raw AWS API responses. A redacted mode is available to strip account IDs and resource names/identifiers.
- **Minimal retention.** If you opt in, Jet1 stores the report summary and the contact email you verified. No raw API responses are stored. See the [Privacy Policy](https://jetonecloud.com/privacy) for details.

## Supported versions

Only the latest released version of Preflight is supported with security fixes. Please update before reporting an issue to confirm it still reproduces.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email **security@jetonecloud.com** with:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal repro is ideal)
- The Preflight version and platform you observed it on

We aim to acknowledge reports within 2 business days and will keep you updated as we investigate and fix. We're happy to credit reporters in release notes if you'd like.

If your finding is specifically that a module or the generated IAM policy requests a permission beyond `Get*`/`List*`/`Describe*`, or that credentials are logged/transmitted anywhere, treat it as critical — please report it right away.

## Verifying releases

Releases are signed and published with checksums. Before running an installer or binary:

1. Download the release artifact and its corresponding `.sig`/`.sha256` file from the [Releases page](https://github.com/jet1-cloud/preflight/releases).
2. Verify the checksum and signature as documented in [`docs/verifying-releases.md`](docs/verifying-releases.md).
3. Prefer `pipx`/`brew`/Docker over `curl | sh` if you'd rather not run a shell script sight-unseen — see [`README.md`](README.md#install).

## Scope

In scope: the `preflight` CLI, its generated IAM policy/role templates, and the opt-in upload endpoint's handling of data in transit and at rest (at a description level — the endpoint's infrastructure is not open source).

Out of scope: vulnerabilities in AWS itself, or in third-party dependencies with their own disclosure process (please report upstream, and let us know so we can track it).
