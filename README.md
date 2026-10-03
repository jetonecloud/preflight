# Preflight

Preflight is a command-line tool that audits your AWS account and tells you what's worth fixing. It looks at how you deploy, what you're spending, and how much of your infrastructure depends on one or two people, then writes up a report you can share with the rest of your team.

It's read-only and open source (Apache-2.0), and it runs on your own machine. Your AWS credentials stay there.

We're [Jet1](https://jetonecloud.com), a managed DevOps team for startups that haven't hired a DevOps engineer yet. Preflight is the audit we run on every first call, packaged so you can run it yourself.

## Getting started

Install it:

```sh
curl -fsSL https://get.preflight.dev | sh
```

You can also install it with `pipx`, `brew`, or Docker (see [`docs/installation.md`](docs/installation.md)). If you don't have the AWS CLI set up locally, you can [run it from AWS CloudShell](docs/cloudshell.md) instead.

To see what a report looks like before pointing it at your account:

```sh
preflight demo
```

When you're ready to scan for real:

1. Deploy [`iam/role.cfn.yaml`](iam/role.cfn.yaml) from the CloudFormation console. It creates a role with the permissions in [`iam/policy.json`](iam/policy.json) and nothing else.
2. Log in to AWS the way you usually do (`aws sso login`, a named profile, and so on). Preflight won't ask you for access keys.
3. Run the scan with the role ARN from the stack's outputs:

```sh
preflight scan --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole --region us-east-1
```

Before it starts, Preflight lists what it's going to read. When it's done, you'll have an HTML report and a JSON export saved locally.

If you'd rather not create the role, you can scan with an existing profile:

```sh
preflight scan --profile my-profile --region us-east-1
```

Preflight checks whether that identity has write or admin access and will warn you if it does. We'd still recommend the dedicated role.

## What it checks

| Area | For example |
|---|---|
| Cost | Unattached EBS volumes and Elastic IPs, idle NAT gateways and load balancers, stopped instances, old snapshots, oversized instances, missing Savings Plans, environments nobody's using |
| Security and IAM | MFA, stale access keys, root account usage, public S3 buckets, open security groups, CloudTrail, encryption defaults |
| Reliability | Single-AZ databases, missing backups, no autoscaling, missing health checks |
| Delivery and IaC | How much is managed by IaC, CloudFormation drift, deploy strategy, `latest` image tags, stale AMIs, SSH-only access |
| Observability | Alarm coverage, log retention, dashboards, tracing |
| Bus factor | Whether changes (from CloudTrail) come from just a few people, how many admins you have, resources with no clear owner |

## Permissions and your data

The IAM policy in [`iam/policy.json`](iam/policy.json) only uses `Get`, `List`, and `Describe` actions, with no wildcards. Each module declares the actions it needs, so you can trim the policy down to just the checks you care about.

Preflight uses the standard AWS credential chain (profiles, SSO, STS, assume-role). It never handles your keys directly and never sends credentials anywhere.

By default, nothing leaves your machine. The one exception is opt-in: you can ask us to email you a copy of the report. If you do, Preflight sends a summary of scores and findings over HTTPS, optionally with account IDs and resource names redacted, after you confirm your email address with a magic link. Run `preflight preview` first to see exactly what would be sent. Raw API responses are never sent or stored.

The dollar figures in the report are estimates. We keep them on the conservative side, and each one shows how it was worked out.

Releases are signed and come with checksums, so you can verify what you're running. [`SECURITY.md`](SECURITY.md) has the full details on data handling and our threat model.

## Contributing

Contributions are welcome. Have a look at [`CONTRIBUTING.md`](CONTRIBUTING.md) and our [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) first.

## License

Apache License 2.0, see [`LICENSE`](LICENSE). Some of the check logic is adapted from other Apache-2.0 and MIT-licensed projects, and they're credited in [`NOTICE`](NOTICE).

## Want help fixing what it finds?

That's what we do at [Jet1](https://jetonecloud.com): deploys, AWS infrastructure, cost work, and on-call, with an SLA, and you own everything we build. If you'd like to talk it through with an engineer, [book a 20-minute call](https://jetonecloud.com/book).
