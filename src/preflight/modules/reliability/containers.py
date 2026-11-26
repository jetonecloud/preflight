"""ECS services, and how many tasks stand between them and an outage.

ECS restarts a task that dies, which makes a service of one feel safe. It
isn't: between the old task stopping and the new one passing its health
check there's nothing serving, and that gap happens on every crash and
every host retirement. A service whose tasks can only land in one subnet
has the same problem one level up.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check
from preflight.modules.reliability.common import (
    MODULE,
    Problem,
    confidence_for,
    environment_caveat,
    non_production,
    too_new,
)

#: DescribeServices takes at most this many services per call.
DESCRIBE_BATCH = 10


def ecs_services_at_risk(ctx: ScanContext) -> Iterator[Finding]:
    """Services with nothing running, a single task, or a single subnet."""
    for region in ctx.regions:
        for cluster in ctx.collect("ecs:ListClusters", "clusterArns", region=region):
            arns = [
                str(arn)
                for arn in ctx.collect(
                    "ecs:ListServices", "serviceArns", region=region, cluster=str(cluster)
                )
            ]
            for start in range(0, len(arns), DESCRIBE_BATCH):
                described = ctx.call(
                    "ecs:DescribeServices",
                    region=region,
                    cluster=str(cluster),
                    services=arns[start : start + DESCRIBE_BATCH],
                    include=["TAGS"],
                )
                for service in described.get("services") or ():
                    finding = _judge(ctx, region, str(cluster), service)
                    if finding is not None:
                        yield finding


def _judge(ctx: ScanContext, region: str, cluster: str, service: dict[str, Any]) -> Finding | None:
    if service.get("status") != "ACTIVE" or int(service.get("desiredCount") or 0) == 0:
        return None
    ctx.looked_at()
    tags = _tags(service.get("tags"))
    if ignored(tags) or non_production(tags) or too_new(ctx, service.get("createdAt")):
        return None
    if any(
        deployment.get("rolloutState") == "IN_PROGRESS"
        for deployment in service.get("deployments") or ()
    ):
        # Mid-deploy, the counts are in motion. Ask again when it's settled.
        return None

    problems = _problems(service)
    if not problems:
        return None
    return _finding(ctx, region, cluster, service, tags, problems)


def _problems(service: dict[str, Any]) -> list[Problem]:
    desired = int(service.get("desiredCount") or 0)
    running = int(service.get("runningCount") or 0)
    found: list[Problem] = []

    if running == 0:
        found.append(
            (
                Severity.HIGH,
                "ECS service with no tasks running",
                f"It wants {desired} task(s) and has none running: whatever it serves "
                "is down, and ECS hasn't been able to start a replacement.",
                "look at the service's events and the last stopped task's reason",
            )
        )
        return found

    if desired == 1 and service.get("schedulingStrategy", "REPLICA") == "REPLICA":
        found.append(
            (
                Severity.MEDIUM,
                "ECS service running a single task",
                "It runs one task. ECS will restart it if it dies, but until the new "
                "one is up and healthy, nothing is serving.",
                "run at least two tasks",
            )
        )

    subnets = (service.get("networkConfiguration") or {}).get("awsvpcConfiguration", {}).get(
        "subnets"
    ) or ()
    if len(subnets) == 1:
        found.append(
            (
                Severity.MEDIUM,
                "ECS service confined to one subnet",
                f"Its tasks can only be placed in {subnets[0]}, and a subnet is in "
                "exactly one Availability Zone.",
                "give it subnets in at least two Availability Zones",
            )
        )

    return found


def _tags(raw: Any) -> dict[str, str]:
    """ECS spells tag keys in lower case, unlike nearly everything else."""
    return {
        str(tag.get("key")): str(tag.get("value", ""))
        for tag in raw or ()
        if tag.get("key") is not None
    }


def _finding(
    ctx: ScanContext,
    region: str,
    cluster: str,
    service: dict[str, Any],
    tags: dict[str, str],
    problems: list[Problem],
) -> Finding:
    name = str(service.get("serviceName"))
    cluster_name = cluster.rsplit("/", 1)[-1]
    severity, title, _, _ = problems[0]
    evidence = [f"Service {name} in cluster {cluster_name}."]
    evidence.extend(line for _, _, line, _ in problems)
    if severity is not Severity.HIGH:
        caveat = environment_caveat(tags)
        if caveat:
            evidence.append(caveat)
    steps = "; ".join(step for _, _, _, step in problems)
    return Finding(
        check="ecs-services-at-risk",
        module=MODULE,
        title=title,
        resource=Resource(
            id=f"{cluster_name}/{name}",
            kind="ecs:service",
            region=region,
            arn=service.get("serviceArn")
            or ctx.arn("ecs", region, f"service/{cluster_name}/{name}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=f"{steps[:1].upper()}{steps[1:]}.",
        confidence=Confidence.HIGH if severity is Severity.HIGH else confidence_for(tags),
        severity=severity,
    )


ECS_SERVICES_AT_RISK = Check(
    key="ecs-services-at-risk",
    title="ECS services one task from down",
    looks_for=(
        "Services with no tasks running, a single task, or only one subnet to place tasks in."
    ),
    actions=("ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices"),
    run=ecs_services_at_risk,
)
