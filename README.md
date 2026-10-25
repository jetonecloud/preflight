# Preflight

Preflight is a command-line tool that audits your AWS account and tells you what's worth fixing. It looks at how you deploy, what you're spending, and how much of your infrastructure depends on one or two people, then writes up a report you can share with the rest of your team.

It's read-only and open source (Apache-2.0), and it runs on your own machine. Your AWS credentials stay there.

We're [Jet1](https://jetonecloud.com), a managed DevOps team for startups that haven't hired a DevOps engineer yet. Preflight is the audit we run on every first call, packaged so you can run it yourself.

## Getting started

Install it:

```sh
curl -fsSL https://jetonecloud.com/preflight | sh
```

You can also install it with `pipx`, `brew`, or Docker (see [`docs/installation.md`](docs/installation.md)). If you don't have the AWS CLI set up locally, you can [run it from AWS CloudShell](docs/cloudshell.md) instead.

To see what a report looks like before pointing it at your account:

```sh
preflight demo
```

When you're ready to scan for real:

1. Pick what you want checked and generate the role it needs:

```sh
preflight scan --modules cost --save
```

   Run `preflight scan` on its own and it'll ask instead: first which checks to run, then which permissions to grant them. Every service the checks need starts selected, and you can switch any of them off with the arrow keys — `--services ec2,rds` does the same thing without the questions. Either way you get a CloudFormation template granting only the read-only actions those checks declare — nothing for the modules you didn't pick. This step makes no AWS calls and needs no credentials, so you can read the whole template before anything touches your account. ([`iam/role.cfn.yaml`](iam/role.cfn.yaml) is the same thing with every module selected.)

2. Deploy the template from the CloudFormation console, or with `aws cloudformation deploy`. The stack's `RoleArn` output is what you pass back to Preflight.
3. Log in to AWS the way you usually do (`aws sso login`, a named profile, and so on). Preflight won't ask you for access keys.
4. Run the scan with the role ARN from the stack's outputs:

```sh
preflight scan --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole --region us-east-1
```

Before it starts, Preflight lists every call it's going to make and asks before making any of them. When it's done, you'll have an HTML report and a JSON export saved locally, and the first three things worth fixing printed in your terminal. Leave `--region` off and it scans every region the account has enabled — waste tends to be in the region you've forgotten about.

If you'd rather not create the role, you can scan with an existing profile, or with whatever credentials are already in the environment:

```sh
preflight scan --profile my-profile --region us-east-1
preflight scan --current           # CloudShell, env vars, an instance role
```

Preflight will tell you when you're scanning as something broader than it needs — the root user especially — and recommend the dedicated role instead.

## What the Cost Check looks for

Nine checks, and what each one costs you:

| Check | Looks for |
|---|---|
| Unattached EBS volumes | Disks attached to nothing, billed every hour |
| Elastic IPs attached to nothing | Public IPv4 addresses you're renting and not using |
| NAT gateways with no traffic | ~$33/month each, with nothing routing through them |
| Load balancers with nothing behind them | No targets registered, or no requests at all |
| Instances stopped for a month or more | Stopped instances whose EBS volumes are still billed |
| Stopped RDS instances | Still charged for storage — and AWS restarts them after 7 days |
| Snapshots nothing is using | Old snapshots whose volume is gone and which no AMI depends on |
| Old manual database snapshots | Manual RDS snapshots nobody is going to restore |
| Instances bigger than their workload | Running instances whose peak CPU never approaches what they're paying for |

Every finding shows its own arithmetic — "500 GB of gp3 at $0.08/GB-month" — so you can check any figure yourself. Estimates use us-east-1 list prices, which are the lowest AWS charges, and ignore any Savings Plans or Reserved Instances you have; they're meant to be numbers you'd be comfortable defending, not the biggest ones we could justify.

Checks keep quiet when they aren't sure. A volume detached three days ago is a migration in progress; a snapshot an AMI depends on is load-bearing; an instance with one busy hour a day is correctly sized. [`docs/cost-check.md`](docs/cost-check.md) has the full list of thresholds and guards.

Already decided about something? Tag it `preflight:ignore` and no check will mention it again.

```sh
preflight scan --list-checks                      # the checks, and the permissions each needs
preflight scan --role-arn <arn> --only idle-nat-gateways
preflight scan --role-arn <arn> --days 30         # a longer look at usage
preflight scan --role-arn <arn> --redact          # a report you can share without sharing your account
```

## Permissions and your data

The IAM policy in [`iam/policy.json`](iam/policy.json) only uses `Get`, `List`, and `Describe` actions, with no wildcards. Each check declares the actions it needs, so the role Preflight generates covers the checks you picked and nothing else — `preflight scan --list-checks` shows exactly which call belongs to which check, and the permission picker lets you cut it down further by service. Nothing with a write verb or a wildcard can reach a generated policy; Preflight refuses to emit one.

That declaration isn't just documentation. While a check runs, it's only allowed to make the calls it declared — anything else is a hard error rather than a quiet extra read — so the permissions you approved and the calls Preflight makes can't drift apart. If a permission is missing, the check that needed it is reported as **skipped**, naming the action, in the terminal and in the report. Nothing is quietly left out.

Preflight uses the standard AWS credential chain (profiles, SSO, STS, assume-role). It never handles your keys directly and never sends credentials anywhere.

Nothing leaves your machine. A scan reads AWS and writes two local files, and that's all it does — there is no telemetry, no upload, and nothing to opt out of. If you want to share a report without sharing your account, `--redact` replaces every account and resource identifier with a stable pseudonym and leaves the findings and the arithmetic intact.

(Emailing yourself a copy of the report, and the `preflight preview` command that would show you the exact payload first, are planned and not built yet. `preflight preview` currently does nothing.)

The dollar figures in the report are estimates. We keep them on the conservative side, and each one shows how it was worked out — see [`docs/cost-check.md`](docs/cost-check.md#how-the-money-is-worked-out).

Releases are signed and come with checksums, so you can verify what you're running. [`SECURITY.md`](SECURITY.md) has the full details on data handling and our threat model.

## Contributing

Contributions are welcome. Have a look at [`CONTRIBUTING.md`](CONTRIBUTING.md) and our [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) first.

## License

Apache License 2.0, see [`LICENSE`](LICENSE). Some of the check logic is adapted from other Apache-2.0 and MIT-licensed projects, and they're credited in [`NOTICE`](NOTICE).

## Want help fixing what it finds?

That's what we do at [Jet1](https://jetonecloud.com): deploys, AWS infrastructure, cost work, and on-call, with an SLA, and you own everything we build. If you'd like to talk it through with an engineer, [book a 20-minute call](https://jetonecloud.com/book).
