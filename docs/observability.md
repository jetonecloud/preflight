# The Observability Check

Three checks about whether anyone would find out when something breaks.
This page is the full reference: what each one looks at, what makes it stay
quiet, and why none of them puts a dollar figure on anything.

Run it on its own:

```sh
preflight scan --modules observability --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole
```

Leave `--modules` off and it runs alongside the Cost and Security Checks. To see the checks
and the exact permissions each one needs, without an account:

```sh
preflight scan --modules observability --list-checks
```

## The checks

| Check | Looks for | Stays quiet when |
|---|---|---|
| `alarms-that-notify-nobody` | Alarms with their actions switched off; alarms with no actions at all; alarms whose only SNS topics are gone or have no confirmed subscribers | The alarm also scales, recovers or runs something; a composite alarm it feeds does the notifying; any one of its topics has a confirmed subscriber; the topic is in another region |
| `unwatched-resources` | Running RDS instances and application/network load balancers that no CloudWatch alarm mentions | An alarm watches its dimension, metric math included; for an Aurora instance, an alarm watches its cluster; it's stopped, provisioning, or less than 7 days old |
| `log-groups-kept-forever` | CloudWatch log groups with no retention period holding at least 1 GB | It has any retention set, holds less than 1 GB, or is less than 7 days old |

Every threshold above is a constant at the top of the file that implements
the check, under [`src/preflight/modules/observability/`](../src/preflight/modules/observability/).

### Alarms that notify nobody

The failure this looks for isn't missing monitoring so much as monitoring
that quietly stopped working. Three shapes of it:

- **Actions switched off.** Usually done to silence an alarm during an
  incident, and forgotten afterwards. High confidence: the API says so.
- **Nowhere to send it.** No alarm actions at all, so going into ALARM only
  shows in the console. Medium confidence, because some alarms are
  deliberately action-free — a CodeDeploy rollback trigger, or one that only
  colours a dashboard. Tag those `preflight:ignore`.
- **A topic nobody reads.** Every SNS topic the alarm publishes to either no
  longer exists or has no confirmed subscription. An email subscription
  nobody clicked to confirm shows as `PendingConfirmation`, and counts as
  nobody. These are reported **once per topic**, listing the alarms that
  depend on it, because one subscription fixes all of them.

An alarm whose actions include anything other than SNS — an Auto Scaling
policy, an EC2 recover or stop action, a Systems Manager action — is doing a
job and isn't flagged. A topic in another region can't be judged from the
region being read, so it's assumed to work.

### Databases and load balancers nothing is watching

Matched on the dimensions alarms watch: `DBInstanceIdentifier` and
`DBClusterIdentifier` for RDS, `LoadBalancer` (the `app/name/id` form) for
ALBs and NLBs. An alarm on a target group that carries the load balancer
dimension counts.

Medium confidence, and it says why: monitoring outside CloudWatch —
Datadog, Grafana, an uptime service — is invisible to it. If that's how the
resource is watched, tag it `preflight:ignore`.

Classic load balancers and gateway load balancers aren't covered yet.

### Log groups kept forever

A log group created by Lambda, ECS or the CloudWatch agent starts at "Never
expire". The finding states what the group costs to store, at $0.03 per
GB-month, as evidence — but claims no saving, because how much a retention
period removes depends on how the data is spread over time, which the API
doesn't say.

## Silencing a finding

Tag the alarm, topic, database, load balancer or log group
`preflight:ignore`, as with every other check. RDS returns its own tags;
everything else here is looked up through `tag:GetResources`, so without
that permission the tag can only silence databases.

## Severity

None of these findings has a dollar figure, so each check sets its own:

| Finding | Severity |
|---|---|
| A topic nobody reads, behind two or more alarms | High |
| A topic nobody reads, behind one alarm | Medium |
| An alarm with its actions switched off | Medium |
| A database or load balancer with no alarm | Medium |
| A log group kept forever, 50 GB or more | Medium |
| An alarm with no actions | Low |
| A log group kept forever, under 50 GB | Low |

The report leaves the money out for these rather than print `$0.00`: an
alarm that pages nobody isn't free, it just isn't priced.

## What the scan reads

| Permission | Used by |
|---|---|
| `sts:GetCallerIdentity` | Every scan, to show you which account it's about to read |
| `ec2:DescribeRegions` | Finding the regions to scan |
| `cloudwatch:DescribeAlarms` | Both alarm checks |
| `sns:ListTopics`, `sns:ListSubscriptions` | Whether an alarm's topic exists and has anyone on the other end. Only called when an alarm publishes to SNS |
| `rds:DescribeDBInstances` | The databases that ought to be watched |
| `elasticloadbalancing:DescribeLoadBalancers` | The load balancers that ought to be watched |
| `logs:DescribeLogGroups` | Retention and stored size |
| `tag:GetResources` | `preflight:ignore` and owner names for everything but databases |

Every one of these was already in [`iam/policy.json`](../iam/policy.json);
the module adds no permission to the full role. A role generated for
Observability alone gets only these.

None of them reads log contents, alarm history or message payloads: the
check sees names, settings, sizes and counts.
