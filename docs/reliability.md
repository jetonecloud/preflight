# The Reliability Check

Five checks about what one failure would take down: a host, a zone, a bad
migration, a task that won't start. This page is the full reference: what
each one looks at, what makes it stay quiet, and how severity is set when
there's no money to set it by.

Run it on its own:

```sh
preflight scan --modules reliability --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole
```

Leave `--modules` off and it runs alongside the Cost, Observability and
Security Checks. To see the checks and the exact permissions each one needs,
without an account:

```sh
preflight scan --modules reliability --list-checks
```

## The checks

| Check | Looks for | Stays quiet when |
|---|---|---|
| `databases-without-backups` | Running RDS instances with backup retention at 0 and no snapshot in the last 2 days | Retention is 1 day or more; any finished snapshot (manual, AWS Backup) is 2 days old or less; it's a read replica or an Aurora instance |
| `single-az-databases` | Running RDS instances with Multi-AZ off; Aurora clusters with a single instance | Multi-AZ is on; the cluster has a reader; it's a read replica; the engine is SQL Server Express, which can't do Multi-AZ |
| `fragile-load-balanced-services` | Target groups behind an active ALB or NLB with every target unhealthy, a single target, or all their targets in one zone | Nothing is registered (that's the Cost Check's); a target is still starting up; an Auto Scaling group manages the target group (one target or one zone only); a target's zone can't be found |
| `ecs-services-at-risk` | ECS services with no tasks running, one task, or one subnet to place tasks in | The service is scaled to zero, is a daemon service, or is mid-deployment |
| `autoscaling-groups-that-cant-heal` | Auto Scaling groups with Launch, Terminate, HealthCheck or ReplaceUnhealthy suspended; EC2-only health checks behind a load balancer; one Availability Zone | The group is parked at zero; only scaling processes are suspended; it has no load balancer (for the health check type) |

All five also stay quiet about anything created in the last 7 days, and
anything tagged as not production (see below). Every threshold above is a
constant at the top of the file that implements the check, under
[`src/preflight/modules/reliability/`](../src/preflight/modules/reliability/).

### Is it production?

A single-AZ database in a sandbox is a sensible saving, and a report that
says otherwise teaches people to stop reading it. Preflight can't know, so
it believes a tag when there is one. It reads `Environment`, `Env`, `Stage`
or `Tier` (in either case):

- `dev`, `development`, `test`, `testing`, `qa`, `staging`, `stage`,
  `sandbox`, `demo`, `preview`, `experiment` or `scratch`: the resource is
  allowed to fall over, and no reliability check mentions it.
- `prod`, `production`, `live` or `prd`: findings are high confidence.
- Anything else, or no tag: findings are medium confidence, and say how to
  tag the resource if it isn't production.

A load balancer's tags and its target group's are read together, so either
one can say.

### Databases with nothing to restore from

Backup retention at 0 means no automated backups and no point-in-time
recovery. That alone isn't the finding: plenty of teams snapshot on their own
schedule, and AWS Backup's snapshots aren't "automated" ones. So the check
asks for the newest finished snapshot of the database, of any kind, and only
speaks when it's more than 2 days old.

| Newest snapshot | Severity |
|---|---|
| None | High |
| Over 30 days old | High |
| 3 to 30 days old | Medium |

Snapshots are only read for databases with backups off, so a healthy account
costs no extra calls.

### Databases with no standby

An RDS instance with Multi-AZ off is down for as long as it takes RDS to
replace a failed host. Aurora keeps its data in three zones whatever you do,
but a cluster of one has nothing to promote when the writer fails, so it's
reported once, as the cluster. Multi-AZ DB clusters have three instances and
pass on their own.

The recommendation is honest about the cost: Multi-AZ roughly doubles the
instance price.

### Load-balanced services one failure from down

For each target group behind an active application or network load balancer,
the check reads target health and counts the targets that are registered and
meant to be serving (draining and unused ones don't count).

- **Every target unhealthy** is high severity and high confidence, whoever
  manages the group: requests are being refused, or sent to targets the load
  balancer itself thinks are broken. The finding quotes AWS's reason, such as
  "Health checks failed with these codes: [404]". A target still in its
  `initial` state is a deploy, not an outage, so its presence keeps the check
  quiet.
- **One target** that no Auto Scaling group manages is medium severity:
  patching it is downtime.
- **Every target in one zone** is medium severity. Zones come from the target
  itself for IP targets and from `ec2:DescribeInstances` for instance
  targets, read once per region and only when needed. A target whose zone
  can't be found gets the benefit of the doubt.

### ECS services one task from down

| Service | Severity |
|---|---|
| Wants tasks and has none running | High |
| Runs one task | Medium |
| Its awsvpc configuration offers one subnet | Medium |

A service mid-deployment is skipped, because its counts are in motion. One
subnet means one zone, so no subnet lookup is needed. Services are described
ten at a time, the API's limit.

### Auto Scaling groups that can't heal

| Problem | Severity |
|---|---|
| Launch, Terminate, HealthCheck or ReplaceUnhealthy suspended | High |
| Behind a load balancer, with EC2 health checks only | Medium |
| One Availability Zone | Medium |

Suspending a process is how people debug a group, and the suspension
outlives the debugging. EC2 health checks replace instances that crash but
not ones that stop answering: the load balancer stops sending them traffic,
and nothing replaces them.

## One finding per resource

A resource with several problems gets one finding, titled by the worst, with
every problem in its evidence and every fix in its recommendation. An Auto
Scaling group with healing suspended *and* only one zone is one thing to fix,
not two lines in the report.

## Silencing a finding

Tag the database, load balancer, target group, ECS service or Auto Scaling
group `preflight:ignore`, or with an environment that isn't production. RDS
instances, ECS services and Auto Scaling groups return their own tags. Load
balancers and target groups are looked up through `tag:GetResources`.

## What the scan reads

| Permission | Used by |
|---|---|
| `sts:GetCallerIdentity` | Every scan, to show you which account it's about to read |
| `ec2:DescribeRegions` | Finding the regions to scan |
| `rds:DescribeDBInstances` | Both database checks |
| `rds:DescribeDBSnapshots` | The newest snapshot of a database with backups off |
| `elasticloadbalancing:DescribeLoadBalancers` | The active load balancers |
| `elasticloadbalancing:DescribeTargetGroups` | What's behind each one |
| `elasticloadbalancing:DescribeTargetHealth` | Which targets are registered, and whether they're healthy |
| `ec2:DescribeInstances` | Which zone an instance target is in |
| `autoscaling:DescribeAutoScalingGroups` | The scaling check, and which target groups a group manages |
| `ecs:ListClusters`, `ecs:ListServices`, `ecs:DescribeServices` | The services, their task counts, subnets and tags |
| `tag:GetResources` | `preflight:ignore`, environment and owner names for load balancers and target groups |

None of them reads data from a database, a container's environment or a task
definition: the check sees names, settings, counts and health states.

Shipping this module removed `ecs:DescribeClusters` from
[`iam/policy.json`](../iam/policy.json), since nothing calls it. Every action
above was already in the policy. A role generated for Reliability alone gets
only the actions above.
