# The Delivery Check

Three checks about whether what's running is what was deployed, and whether
it could be deployed again: stacks the next deploy will trip over, services
that pick up whatever was pushed last, and instances nothing could launch a
copy of. This page is the full reference: what each one looks at, what keeps
it quiet, and how severity is set when there's no money to set it by.

Run it on its own:

```sh
preflight scan --modules delivery --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole
```

Leave `--modules` off and it runs alongside the Cost, Observability,
Security and Reliability Checks. To see the checks and the exact permissions
each one needs, without an account:

```sh
preflight scan --modules delivery --list-checks
```

## The checks

| Check | Looks for | Stays quiet when |
|---|---|---|
| `cloudformation-stacks-at-risk` | Stacks stuck after a failed create, update, delete or import; stacks whose last drift detection found resources modified or deleted by hand | The failure is less than a day old; it's a nested stack (its parent is reported); drift was never checked, or came back in sync |
| `services-on-moving-tags` | ECS services whose task definition runs `:latest` or an untagged image | The image is pinned by digest; it's `:latest` in one of the account's own ECR repositories with immutable tags; the service is scaled to zero |
| `instances-you-couldnt-rebuild` | Running instances launched from an AMI that's been deregistered or disabled, or was built more than 365 days ago | The instance is stopped; for an old (but existing) image, the instance is tagged as not production |

All three stay quiet about anything tagged `preflight:ignore`. The ECS and
instance checks also leave alone anything launched in the last 7 days.
Every threshold above is a constant at the top of the file that implements
the check, under
[`src/preflight/modules/delivery/`](../src/preflight/modules/delivery/).

### CloudFormation stacks you can't deploy with confidence

| Stack | Severity |
|---|---|
| `UPDATE_ROLLBACK_FAILED` | High |
| `ROLLBACK_COMPLETE`, `ROLLBACK_FAILED`, `DELETE_FAILED`, `IMPORT_ROLLBACK_FAILED` | Medium |
| Last drift detection found resources `MODIFIED` or `DELETED` | Medium |

`UPDATE_ROLLBACK_FAILED` is the dangerous one: CloudFormation refuses every
update until someone continues the rollback by hand, which is usually found
out mid-incident, when the fix needs deploying. A stack left in
`ROLLBACK_COMPLETE` can only be deleted, so the next deploy to that name
fails.

**Preflight never starts drift detection.** `DetectStackDrift` is a write,
and the role has none. The check reports what the stack's last detection
found, names the first three drifted resources, and says how long ago that
detection ran. Over 30 days and the finding drops to medium confidence,
since the drift may have been put right since. A stack nobody has ever run
drift detection on says nothing, which is a reason to run it now and then.

A stuck stack that has also drifted is one finding, titled by the stuck
state, with both fixes in the recommendation.

### Services that deploy a moving image tag

`:latest` (or no tag, which means the same thing) is a pointer anyone with
push access can move. The service doesn't change when it moves, but the next
task ECS starts does: a crash, a scale-out or a host retirement quietly
deploys whatever was pushed last, with no record of it in the service. And
rolling back means finding and re-pushing the old image, since no task
definition names it.

The check reads each running service's current task definition, once per
revision however many services share it, and flags any container whose
image is untagged or tagged `latest`. Two things clear it:

- **A digest.** `app@sha256:...` is pinned, whatever tag sits next to it.
- **Immutable tags in your own ECR.** For an image in one of the scanned
  account's ECR repositories, the check reads the repository's tag
  mutability. With `IMMUTABLE` (or `IMMUTABLE_WITH_EXCLUSION`), `latest`
  can't be overwritten once it's pushed, so it's as good as a version.
  Images in other accounts' registries, Docker Hub or GHCR get no such
  benefit of the doubt.

Findings are medium severity. They're high confidence when the service is
tagged production, medium otherwise, and services tagged as non-production
aren't reported: a preview environment pulling `:latest` is how previews
work. Only `latest` counts as a moving tag. `main`, `stable` or `prod` may
well be moved on every push, but they may also be versions, and the check
can't tell.

### Instances you couldn't launch again

An instance is only as replaceable as the image it was launched from.

| Image | Severity | Confidence |
|---|---|---|
| Deregistered or disabled | Medium | High |
| Built more than 365 days ago | Low | Medium |

If the AMI is gone, losing the instance means rebuilding it from memory. If
it's more than a year old, whatever has been patched, installed or
configured since lives only on the running box. That's low severity because
plenty of instances are rebuilt by provisioning code rather than from their
image, and the check can't see that.

There's one finding per image, naming the first three instances launched
from it, because the fix is a new image rather than a change to each
instance. Images are described a hundred at a time, including deprecated and
disabled ones. An ID AWS has never heard of fails a whole request, so that
batch is asked about again one image at a time.

An old image only matters for instances not tagged as non-production. A
missing image matters everywhere, because a staging box nobody can rebuild
is still a staging box nobody can rebuild.

## One finding per resource

As in the Reliability Check, a resource with several problems gets one
finding, titled by the worst, with every problem in its evidence and every
fix in its recommendation.

## Silencing a finding

Tag the stack, ECS service or instance `preflight:ignore`. For the image
check, an image is only reported for instances that aren't ignored, so
ignoring every instance launched from an image silences it. ECS services
and instances can also be tagged with an environment that isn't production
(`Environment=dev`, `staging` and the like: the same tags and values the
[Reliability Check](reliability.md#is-it-production) reads).

## What the scan reads

| Permission | Used by |
|---|---|
| `sts:GetCallerIdentity` | Every scan, to show you which account it's about to read |
| `ec2:DescribeRegions` | Finding the regions to scan |
| `cloudformation:DescribeStacks` | Each stack's status, tags and last drift status |
| `cloudformation:DescribeStackResourceDrifts` | Which resources drifted, only for stacks that have |
| `ecs:ListClusters`, `ecs:ListServices`, `ecs:DescribeServices` | The services, their task definitions and tags |
| `ecs:DescribeTaskDefinition` | The image each container runs |
| `ecr:DescribeRepositories` | Whether an ECR repository's tags can move |
| `ec2:DescribeInstances` | The running instances and the AMI each was launched from |
| `ec2:DescribeImages` | Whether that AMI still exists, and when it was built |

None of them reads a template, a parameter, a container's environment or
anything on an instance. A task definition does carry environment variables,
and the check reads only the image name from it; nothing else from it reaches
the report or the JSON.

Shipping this module added `ecs:DescribeTaskDefinition` to
[`iam/policy.json`](../iam/policy.json) and removed six actions the planned
module had declared and nothing calls: `cloudformation:ListStacks`,
`cloudformation:DescribeStackDriftDetectionStatus`, `ecr:DescribeImages`,
`ec2:DescribeLaunchTemplates`, `codedeploy:ListApplications` and
`codedeploy:GetDeploymentConfig`. A role generated for Delivery alone gets
only the actions above.
