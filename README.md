# Preflight

**Free, open-source, read-only AWS audit CLI.** Run it on your laptop and get the first three things to fix in **deploys, cost, and bus factor** — in plain language, in under 5 minutes. Your AWS credentials never leave your machine.

Built by [Jet1](https://jetonecloud.com) — a managed DevOps team for startups that haven't hired a DevOps engineer yet.

```
preflight scan
```

## Why

Most AWS audit tools dump hundreds of raw findings. Preflight asks three questions instead:

1. **Deploys** — Are releases risky, manual, or stuck to a maintenance window?
2. **Cost** — Where is money being wasted, and how much (conservatively estimated)?
3. **Bus factor** — Does only one person understand this setup?

It scores each 0–100, and tells you the **top 3 fixes** first. Everything else is available in the detailed report if you want it.

## Principles

- **Read-only, always.** The IAM policy ([`iam/policy.json`](iam/policy.json)) contains only `Get*`, `List*`, `Describe*` actions. No wildcards, no write permissions, no exceptions.
- **Credentials never leave your machine.** Preflight uses the standard AWS credential chain (profile, SSO, STS, assume-role). It never asks for access keys and never transmits credentials.
- **Nothing is sent anywhere without your explicit consent.** The local HTML/JSON report is the default and only output. Sending a summary to Jet1 (so we can email it to you) is opt-in, and `preflight preview` shows exactly what would be sent before you agree to anything.
- **Open source and inspectable.** Apache-2.0. Releases are signed with checksums so you can verify what you run.
- **Honest estimates.** Dollar figures are conservative, labeled as estimates, and show their derivation.

See [`SECURITY.md`](SECURITY.md) for the full data-handling and threat model.

## Install

```sh
curl -fsSL https://get.preflight.dev | sh
```

Also available via `pipx`, `brew`, and Docker. See [`docs/installation.md`](docs/installation.md).

Don't have AWS CLI access configured? Run it from [AWS CloudShell](docs/cloudshell.md) — no local install needed.

## Usage

```sh
# See a sample report with no AWS access required
preflight demo

# Run a real scan against your default AWS profile
preflight scan

# Run against a specific profile/region
preflight scan --profile my-profile --region us-east-1

# See exactly what would be sent before opting in to email delivery
preflight preview
```

Preflight will tell you upfront what it's about to read, check that your credentials are read-only (and warn you if they're not), and generate a self-contained HTML report plus a JSON export.

## What it checks

| Module | Examples |
|---|---|
| **Cost** | Unattached EBS/EIPs, idle NAT gateways & load balancers, stopped instances, old snapshots, oversized instances, missing Savings Plans, forgotten environments |
| **Security / IAM** | MFA, stale access keys, root account usage, public S3 buckets, open security groups, CloudTrail, encryption defaults |
| **Reliability** | Single-AZ databases, missing backups, no autoscaling, missing health checks |
| **Delivery & IaC** | IaC coverage, CloudFormation drift, deploy strategy, `latest` image tags, stale AMIs, SSH-only access |
| **Observability** | Alarm coverage, log retention, dashboards, tracing |
| **Bus factor** | Change concentration across principals (via CloudTrail), admin count, unowned resources |

Each module declares the exact IAM actions it uses — see [`iam/policy.json`](iam/policy.json) — so you can opt in per module.

## Required IAM permissions

Preflight ships a least-privilege, read-only IAM policy and an optional CloudFormation stack that creates a cross-account role for it:

- [`iam/policy.json`](iam/policy.json) — the managed policy
- [`iam/role.cfn.yaml`](iam/role.cfn.yaml) — a CloudFormation template for a dedicated read-only role

If the credentials you run Preflight with have write or admin access, it will warn you and recommend switching to the read-only role.

## Report and data handling

Preflight always writes a local, self-contained HTML report and a JSON export. If you choose to email yourself a copy via Jet1, it sends a **summary only** (scores and findings, optionally redacted of account IDs and resource names) over HTTPS, after you confirm via `preflight preview` and verify your email with a magic link. Raw API responses and credentials are never transmitted or stored. Full details in [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Please read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) before participating.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Some check logic is adapted from other Apache-2.0/MIT-licensed open-source projects; attribution is tracked in [`NOTICE`](NOTICE).

## About Jet1

[Jet1](https://jetonecloud.com) is "the DevOps team you keep meaning to hire" — deploys, AWS/infrastructure, cost optimization, and on-call, SLA-backed, with everything owned by you. Preflight is the free version of the audit we do on every first call. If you'd rather talk to a human: [book 20 minutes with an engineer](https://jetonecloud.com/book).
