# The Cost Check

Nine checks that look for things you're paying for and not using. This page
is the full reference: what each one looks at, what makes it stay quiet, and
how the dollar figures are worked out.

Run it:

```sh
preflight scan --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole
```

See the checks and the exact permissions each needs, without an account:

```sh
preflight scan --list-checks
```

## The checks

| Check | Looks for | Stays quiet when |
|---|---|---|
| `unattached-ebs-volumes` | Volumes in the `available` state — attached to nothing, billed anyway | The volume is less than 7 days old |
| `unassociated-public-ips` | Elastic IPs with no instance, interface or association | It's a BYOIP address, which isn't billed at the Amazon rate |
| `idle-nat-gateways` | NAT gateways with no bytes **and** no connections over the window | Any traffic at all, or the gateway is younger than the window |
| `idle-load-balancers` | ALB/NLB/GWLB with no target groups, no registered targets, or no requests; Classic LBs with no instances | Healthy targets *and* traffic, or CloudWatch has no data to judge by |
| `long-stopped-instances` | Instances stopped 30+ days whose EBS volumes are still billed | Stopped more recently, managed by an Auto Scaling group, or no volumes attached |
| `stopped-databases` | RDS instances that are stopped but still charged for storage | The instance is running |
| `old-snapshots` | EBS snapshots 90+ days old whose source volume is gone, or 365+ days old | **Any AMI references the snapshot**, or it's still being taken |
| `old-database-snapshots` | Manual RDS snapshots 180+ days old | It's an automated snapshot — that's the retention policy working |
| `oversized-instances` | Running instances whose peak CPU stayed under 10% for the whole window | Fewer than half the expected datapoints, a single busy hour, 50 GB/day of inbound traffic, spot or dedicated capacity, or no price for the smaller size |

Every threshold above is a constant at the top of the file that implements
the check, under [`src/preflight/modules/cost/`](../src/preflight/modules/cost/).

## Silencing a finding

Tag the resource `preflight:ignore` and no check will mention it again. The
value is free text and a good place to say why:

```sh
aws ec2 create-tags --resources vol-0abc123 \
  --tags Key=preflight:ignore,Value="kept for the 2024 audit"
```

`preflight-ignore` and `PreflightIgnore` work too. To switch the tag off
without deleting it, set the value to `false`, `no`, `0` or `off`.

Load balancer tags are read through `tag:GetResources`; everything else uses
the tags its own API returns.

## How the money is worked out

Every finding shows its own arithmetic — "500 GB of gp3 at $0.08/GB-month" —
so you can check any figure against the AWS pricing page without taking our
word for it. Four things are true of all of them:

- **They're us-east-1 list prices.** us-east-1 is at or near the cheapest
  region for everything priced here, so a volume in eu-west-2 priced at
  us-east-1 rates understates the saving rather than inflating it.
- **No discounts are modelled.** Savings Plans, Reserved Instances, credits,
  private pricing and EDP discounts aren't visible to a read-only scan and
  aren't guessed at. If you have them, the real saving is lower than the
  figure — and the effort to capture it is the same.
- **Snapshots are discounted for being incremental.** A snapshot of a 300 GB
  volume rarely stores 300 GB, so snapshots are costed at a third of their
  volume's size. That's a guess, and it's a guess in your favour.
- **A figure that can't be known isn't invented.** An instance type neither
  the pricing API nor the built-in table can price produces a finding with no
  dollar amount rather than a plausible-looking number.

The price table lives in [`src/preflight/core/pricing.py`](../src/preflight/core/pricing.py)
and carries the date it was last checked. Instance rates come from
`pricing:GetProducts` where that permission was granted, and from a built-in
table of common types where it wasn't — each finding says which.

## Severity

From what it costs per month, unless a check overrides it:

| Severity | Monthly |
|---|---|
| High | $100 or more |
| Medium | $20 to $100 |
| Low | under $20 |

Two checks set a floor instead. A stopped RDS instance is at least medium
whatever its storage costs, because the surprise is that AWS restarts it
after seven days. A Classic load balancer is at least medium because the
$18 is the smaller half of the problem.

**Confidence** is separate, and it's about whether the finding is real rather
than how much it's worth. `high` means the API said so outright — a volume
whose state is `available` is unattached, full stop. `medium` means it was
inferred from usage metrics, which can be wrong for something seasonal.

## What the scan reads

| Permission | Used by |
|---|---|
| `sts:GetCallerIdentity` | Every scan, to show you which account it's about to read |
| `ec2:DescribeRegions` | Finding the regions to scan |
| `ec2:DescribeVolumes` | Unattached volumes, stopped instances, old snapshots |
| `ec2:DescribeAddresses` | Elastic IPs |
| `ec2:DescribeNatGateways` | NAT gateways |
| `ec2:DescribeInstances` | Stopped and oversized instances |
| `ec2:DescribeSnapshots`, `ec2:DescribeImages` | Old snapshots, and the AMI guard |
| `elasticloadbalancing:Describe*` | Load balancers and their targets |
| `autoscaling:DescribeAutoScalingGroups` | Knowing which instances a group manages |
| `rds:DescribeDBInstances`, `rds:DescribeDBSnapshots` | Databases and their snapshots |
| `cloudwatch:GetMetricStatistics` | Whether anything is actually using it |
| `pricing:GetProducts` | Instance prices |
| `ce:GetCostAndUsage` | Last month's bill, so findings can be put in proportion |
| `tag:GetResources` | Owner names for load balancers |

A check can only make the calls it declares — the scan runner enforces it, so
the role you read before deploying is the whole list. `preflight scan
--list-checks` prints the same mapping from the code.

## When something can't be read

A check that hits a missing permission is reported as **skipped**, with the
action it needed, both in the terminal and in a "What we couldn't see"
section of the report. It is never silently dropped and never guessed around:
a cost report that quietly omits a region is worse than one that admits it
couldn't look.

The same goes for regions. If one won't answer — not enabled, endpoint
unreachable — the scan carries on and the report names it.

Two permissions are optional extras rather than requirements: `tag:GetResources`
(you lose owner names) and `ce:GetCostAndUsage` (you lose the comparison
against last month's bill). Neither stops a scan.

## Options worth knowing

```sh
# Just one region, or a few
preflight scan --role-arn <arn> --region us-east-1,eu-west-1

# A longer look at usage, for a workload with a monthly rhythm
preflight scan --role-arn <arn> --days 30

# One check at a time
preflight scan --role-arn <arn> --only unattached-ebs-volumes

# Something you can share without sharing your account
preflight scan --role-arn <arn> --redact

# JSON only, no questions, for a scheduled job
preflight scan --role-arn <arn> --format json --yes --out ./audits
```

With no `--region`, every region the account has enabled is scanned — waste
tends to be in the region you've forgotten about.

## The JSON

`--format json` writes a stable, versioned document (`schema_version: 1`)
next to the HTML. Finding IDs are stable across scans — same resource, same
check, same string — so two reports can be diffed to see what actually got
fixed.

```jsonc
{
  "schema_version": 1,
  "summary": { "estimated_monthly_savings_usd": 529.76, "by_severity": {...} },
  "checks":   [ { "key": "...", "status": "ran|skipped|failed", "resources_examined": 5 } ],
  "findings": [ { "id": "cost/unattached-ebs-volumes/us-east-1/vol-0abc",
                  "estimated_monthly_savings_usd": 40.0,
                  "estimate_basis": "500 GB of gp3 at $0.0800/GB-month (...)",
                  "evidence": [...], "recommendation": "..." } ],
  "missing_actions": []
}
```
