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

Before it starts, Preflight lists what it's going to read. When it's done, you'll have an HTML report and a JSON export saved locally.

If you'd rather not create the role, you can scan with an existing profile:

```sh
preflight scan --profile my-profile --region us-east-1
```

Preflight checks whether that identity has write or admin access and will warn you if it does. We'd still recommend the dedicated role.

## Permissions and your data

The IAM policy in [`iam/policy.json`](iam/policy.json) only uses `Get`, `List`, and `Describe` actions, with no wildcards. Each module declares the actions it needs, so the role Preflight generates covers the checks you picked and nothing else — `preflight scan --list-modules` shows what each one asks for, and the permission picker lets you cut it down further by service. Nothing with a write verb or a wildcard can reach a generated policy; Preflight refuses to emit one.

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
