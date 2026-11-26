# Preflight

Preflight is a command-line tool that audits your AWS account and tells you what's worth fixing. It looks at how you deploy, what you're spending, and how much of your infrastructure depends on one or two people, then prints you a report you can read, diff, or paste into a ticket.

It's read-only and open source (Apache-2.0), and it runs on your own machine. Your AWS credentials stay there.

![`preflight demo` run in a terminal, showing the checks running and the cost report](docs/assets/demo.gif)

## Getting started

```sh
curl -fsSL https://jetonecloud.com/preflight | sh
preflight demo     # see what a report looks like, no account needed
```

`pipx`, `uv`, Homebrew and Docker work too — see [`docs/installation.md`](docs/installation.md). No AWS CLI locally? [Run it from CloudShell](docs/cloudshell.md).

## Scanning your account

1. **Generate the role.** This step makes no AWS calls and needs no credentials, so you can read the whole template first:

   ```sh
   preflight scan --modules cost --save
   ```

   Run `preflight scan` with no flags and it asks instead — which checks to run, then which permissions to grant them. You get a CloudFormation template with only the read-only actions those checks declare; `--services ec2,rds` narrows it further. ([`iam/role.cfn.yaml`](iam/role.cfn.yaml) is the same thing with everything selected.)

2. **Deploy it** from the CloudFormation console or with `aws cloudformation deploy`, and grab the stack's `RoleArn` output.

3. **Log in as you normally do** (`aws sso login`, a named profile) and scan:

   ```sh
   preflight scan --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole
   ```

Preflight lists every call it's going to make and asks before making any of them. Leave `--region` off and it scans every region the account has enabled — waste tends to be in the region you've forgotten about.

Don't want to create the role? `--profile my-profile`, or `--current` for CloudShell, env vars or an instance role. Preflight will say so when you're scanning as something broader than it needs — the root user especially.

## Where the report goes

Same report either way, off the same scan:

- **In the terminal** (the default) — a section at a time, arrow keys to move, `a` for the whole thing, `q` to leave. Plain ASCII tables. Down a pipe or in CI, every section just prints in order.
- **As a PDF**, for when the person who needs to read it isn't the person who ran it. Paginated, with a contents page and every finding in full. Set in Helvetica, with a teal accent and severity in colour: a document to read and argue about, not a dashboard. Preflight writes it directly — no browser, no rendering engine, no links out, nothing fetched when it's opened.

Alongside either, a versioned JSON export you can diff between scans.

```sh
preflight scan --role-arn <arn> --pdf            # PDF instead of paging it here
preflight scan --role-arn <arn> --terminal       # here, without being asked
preflight scan --role-arn <arn> --pdf --no-json  # the PDF and nothing else
```

Each flag answers one question, so `--pdf` alone still asks about the JSON. Where there's nobody to ask — a pipe, CI, `--yes` — you get the terminal report and the JSON. `--out <dir>` puts the files somewhere else.

## Did it work?

Scan again after fixing things, and compare:

```sh
preflight diff                  # the last two scans in this directory
preflight diff --fail-on-new    # exit 1 if anything new turned up, for CI
```

It reads the two JSON exports — no AWS calls — and says what was fixed, what's new, and what moved, with the monthly figure fixed when there is one. A finding is only called fixed if the later scan looked for it: a skipped check or a region left out puts it under *can't tell* instead. [`docs/compare.md`](docs/compare.md) has the details.

## What the Cost Check looks for

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

Every finding shows its own arithmetic — "500 GB of gp3 at $0.08/GB-month" — so you can check any figure yourself. Estimates use us-east-1 list prices and ignore Savings Plans and Reserved Instances: numbers you'd be comfortable defending, not the biggest ones we could justify.

Checks keep quiet when they aren't sure. A volume detached three days ago is a migration in progress; a snapshot an AMI depends on is load-bearing. [`docs/cost-check.md`](docs/cost-check.md) has the thresholds and guards. Already decided about something? Tag it `preflight:ignore` and no check will mention it again.

```sh
preflight scan --list-checks                      # the checks, and what each one needs
preflight scan --role-arn <arn> --only idle-nat-gateways
preflight scan --role-arn <arn> --days 30         # a longer look at usage
preflight scan --role-arn <arn> --redact          # shareable without sharing your account
```

## What the Observability Check looks for

Monitoring rarely goes missing outright. It quietly stops working.

| Check | Looks for |
|---|---|
| Alarms that notify nobody | Actions switched off, nowhere to send it, or a topic with no confirmed subscriber |
| Databases and load balancers nothing is watching | Running RDS instances, ALBs and NLBs that no CloudWatch alarm mentions |
| Log groups kept forever | No retention period, a gigabyte or more and growing |

None of these comes with a dollar figure, and the report doesn't invent one. The same guards apply: an alarm that scales something is doing its job, a composite alarm's children don't need actions of their own, and a topic in another region gets the benefit of the doubt. [`docs/observability.md`](docs/observability.md) has the details.

```sh
preflight scan --role-arn <arn> --modules observability   # just this one
```

## What the Security Check looks for

Who can get into the account, and what's been left open.

| Check | Looks for |
|---|---|
| Root user unguarded | No MFA on the root user, or access keys of its own |
| Public buckets | Buckets S3 itself reports as public, and buckets nothing stops going public |
| Security groups open to the internet | Databases, RDP, Redis and the like reachable from anywhere, on groups something is using |
| Console users without MFA | IAM users who sign in with a password alone |
| Stale access keys | Active keys nobody has used in months, or used for a year unrotated |
| CloudTrail coverage | Regions no trail is recording, and trails that have stopped logging |

No dollar figures here either. The guards still hold: 443 open to the world is a web server doing its job, a group nothing uses isn't exposed, a user who started this week gets a week to set up MFA, and one logging trail is enough. [`docs/security.md`](docs/security.md) has the details.

```sh
preflight scan --role-arn <arn> --modules security   # just this one
```

## What the Reliability Check looks for

What one failure would take down: a host, a zone, a bad migration.

| Check | Looks for |
|---|---|
| Databases with nothing to restore from | Backups switched off, and no recent snapshot of any kind either |
| Databases with no standby | Multi-AZ off, or an Aurora cluster with nothing to fail over to |
| Load-balanced services one failure from down | Every target failing its health check, a lone target nothing replaces, or every target in one zone |
| ECS services one task from down | No tasks running, a single task, or a single subnet |
| Auto Scaling groups that can't heal | Replacement suspended, deaf to the load balancer's health checks, or confined to one zone |

No dollar figures. Anything tagged `Environment=dev`, `staging` or similar is allowed to fall over and isn't mentioned; anything tagged production is reported with high confidence. The other guards: a nightly snapshot counts as a backup, a target group an Auto Scaling group manages can have one target, and a service mid-deploy isn't judged on its counts. [`docs/reliability.md`](docs/reliability.md) has the details.

```sh
preflight scan --role-arn <arn> --modules reliability   # just this one
```

## What the Delivery Check looks for

Whether what's running is what was deployed, and could be deployed again.

| Check | Looks for |
|---|---|
| CloudFormation stacks you can't deploy with confidence | Stacks stuck after a failed deploy, and stacks whose last drift detection found hand edits |
| Services that deploy a moving image tag | ECS services running `:latest` or an untagged image, which the next restart may quietly change |
| Instances you couldn't launch again | Running instances whose AMI has been deregistered, or was built more than a year ago |

No dollar figures. Preflight never starts drift detection, which is a write: it reports what the last one found and how long ago. An image pinned by digest, or `:latest` in an ECR repository with immutable tags, can't move, so neither is reported. [`docs/delivery.md`](docs/delivery.md) has the details.

```sh
preflight scan --role-arn <arn> --modules delivery   # just this one
```

## Permissions and your data

[`iam/policy.json`](iam/policy.json) uses only `Get`, `List` and `Describe` actions, with no wildcards. Each check declares what it needs, so a generated role covers the checks you picked and nothing else — Preflight refuses to emit a policy containing a write verb or a wildcard.

That declaration is enforced at runtime too: a check may only make the calls it declared, and anything else is a hard error rather than a quiet extra read. If a permission is missing, the check is reported as **skipped** with the action named. Nothing is quietly left out.

Preflight uses the standard AWS credential chain (profiles, SSO, STS, assume-role) and never handles your keys directly. A scan reads AWS, prints the report, and writes the local files you asked for — no telemetry, no upload, nothing to opt out of. `--redact` replaces every account and resource identifier with a stable pseudonym, leaving the findings and arithmetic intact.

Email delivery, and the `preflight preview` command that would show you the exact payload first, are planned and not built yet — `preflight preview` currently does nothing.

Releases are signed and come with checksums. [`SECURITY.md`](SECURITY.md) has the full data-handling details and our threat model.

## Contributing

Welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

Apache License 2.0, see [`LICENSE`](LICENSE). Some check logic is adapted from other Apache-2.0 and MIT-licensed projects, credited in [`NOTICE`](NOTICE).

## Want help fixing what it finds?

That's what we do at [Jet1](https://jetonecloud.com): deploys, AWS infrastructure, cost work, and on-call, with an SLA, and you own everything we build. [Book a 20-minute call](https://jetonecloud.com/book).
