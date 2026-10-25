# Security Policy

Preflight is a read-only auditing tool that runs against your AWS account. Security and trust are the product — read this before running it against anything you care about.

## Threat model and guarantees

- **Read-only by construction.** The published IAM policy ([`iam/policy.json`](iam/policy.json)) contains only `Get*`, `List*`, and `Describe*` actions. There is no wildcard `*` action, and no action that creates, modifies, or deletes any AWS resource. If you find one that does, it's a bug — report it (see below).
- **A check can only make the calls it declared.** Each check declares its IAM actions, and the scan runner refuses any call outside that list at runtime. The permissions you read before deploying the role are therefore the complete set of calls Preflight can make, not a best-effort description of them. A check that is denied a permission it needs is reported as skipped, naming the action; it is never silently dropped or worked around.
- **Credentials never leave your machine.** Preflight uses the standard AWS SDK credential chain (environment variables, shared config/profile, SSO, instance/task role, `assume-role`). It never prompts for or accepts a pasted access key/secret, never writes credentials to disk or logs, and never transmits them anywhere.
- **Identity caution, not an audit.** Before reading anything, Preflight shows you the identity it's running as. If that's the account root user, it says so plainly; if it's anything other than the dedicated `PreflightReadOnlyRole`, it tells you it *cannot* tell what else that identity is allowed to do and recommends the role in [`iam/role.cfn.yaml`](iam/role.cfn.yaml) instead. Enumerating an identity's own permissions would require `iam:SimulatePrincipalPolicy`, which Preflight deliberately does not ask for.
- **Nothing leaves your machine.** A scan reads AWS and writes a local HTML and JSON report. There is no telemetry and no upload. `--redact` replaces account and resource identifiers with stable pseudonyms if you want to share a report. (Opt-in email delivery via a Jet1-hosted endpoint, and the `preflight preview` command that would show you the exact payload before you confirm, are planned; neither is implemented, and `preflight preview` currently does nothing.)
- **Summaries, not raw data.** Reports contain findings, evidence and estimates derived from API responses — never the raw responses themselves. This holds for the local files today, and will hold for the opt-in upload if and when it ships.
- **Minimal retention.** Jet1 stores nothing today, because nothing is sent. If you later opt in to email delivery, Jet1 would store the report summary and the contact email you verified, and no raw API responses. See the [Privacy Policy](https://jetonecloud.com/privacy) for details.

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

Every release carries a `checksums.txt` and a signed build provenance attestation tying each binary to the workflow run and commit that produced it. Before running an installer or binary:

1. Download the binary and `checksums.txt` from the [Releases page](https://github.com/jetonecloud/preflight/releases), then check it:

   ```sh
   sha256sum --check --ignore-missing checksums.txt
   ```

   The `curl | sh` installer does this for you and refuses to install on a mismatch.

2. Verify the provenance — this is what proves it was built from this repository, by our release workflow, and not uploaded by hand:

   ```sh
   gh attestation verify preflight-linux-x86_64 --repo jetonecloud/preflight
   ```

3. Prefer `pipx`/`brew`/Docker over `curl | sh` if you'd rather not run a shell script sight-unseen — see [`README.md`](README.md#getting-started). The installer is published as a release asset too, so you can read the exact version you're about to run.

## Scope

In scope: the `preflight` CLI, its generated IAM policy/role templates, and the opt-in upload endpoint's handling of data in transit and at rest (at a description level — the endpoint's infrastructure is not open source).

Out of scope: vulnerabilities in AWS itself, or in third-party dependencies with their own disclosure process (please report upstream, and let us know so we can track it).
