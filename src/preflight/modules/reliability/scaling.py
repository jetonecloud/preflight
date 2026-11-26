"""Auto Scaling groups, and whether they can still do the one thing they're for.

An Auto Scaling group's real job is less scaling than replacing: an instance
dies, the group notices, and a new one takes its place without anyone being
woken. That only works if the group is allowed to launch, can tell an instance
is broken, and has somewhere else to put the new one. Each of those is a
setting that's easy to get wrong once and never look at again.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored, tags_to_dict
from preflight.modules.base import Check
from preflight.modules.reliability.common import (
    MODULE,
    confidence_for,
    environment_caveat,
    non_production,
    too_new,
)

#: (severity, title, evidence, the step that fixes it)
Problem = tuple[Severity, str, str, str]

#: Suspending any of these stops a group from replacing what's broken.
HEALING_PROCESSES = ("Launch", "Terminate", "HealthCheck", "ReplaceUnhealthy")


def autoscaling_groups_that_cant_heal(ctx: ScanContext) -> Iterator[Finding]:
    """Groups that can't replace a broken instance, or can only do it in one zone."""
    for region in ctx.regions:
        for group in ctx.collect(
            "autoscaling:DescribeAutoScalingGroups", "AutoScalingGroups", region=region
        ):
            if int(group.get("DesiredCapacity") or 0) == 0:
                # Parked on purpose: there's nothing running to heal.
                continue
            ctx.looked_at()
            tags = tags_to_dict(group.get("Tags"))
            if ignored(tags) or non_production(tags):
                continue
            if too_new(ctx, group.get("CreatedTime")):
                continue
            problems = _problems(group)
            if problems:
                yield _finding(ctx, region, group, tags, problems)


def _problems(group: dict[str, Any]) -> list[Problem]:
    """Everything wrong with the group, worst first."""
    found: list[Problem] = []

    suspended = sorted(
        str(process.get("ProcessName"))
        for process in group.get("SuspendedProcesses") or ()
        if process.get("ProcessName") in HEALING_PROCESSES
    )
    if suspended:
        found.append(
            (
                Severity.HIGH,
                "Auto Scaling group with healing switched off",
                f"{', '.join(suspended)} {'is' if len(suspended) == 1 else 'are'} "
                "suspended, so an instance that fails stays failed. Processes are "
                "usually suspended to debug something, and left that way.",
                "resume the suspended processes",
            )
        )

    balanced = bool(group.get("TargetGroupARNs") or group.get("LoadBalancerNames"))
    if balanced and group.get("HealthCheckType", "EC2") == "EC2":
        found.append(
            (
                Severity.MEDIUM,
                "Auto Scaling group that ignores its load balancer",
                "It sits behind a load balancer but only uses EC2 health checks, so "
                "it replaces instances that crash, not ones that stop answering. The "
                "load balancer stops sending them traffic; nothing replaces them.",
                "set the health check type to ELB, with a grace period",
            )
        )

    zones = list(group.get("AvailabilityZones") or ())
    if len(zones) == 1:
        found.append(
            (
                Severity.MEDIUM,
                "Auto Scaling group confined to one zone",
                f"Every instance launches in {zones[0]}. If that zone has trouble, "
                "the group has nowhere else to put replacements.",
                "add subnets in at least one more Availability Zone",
            )
        )

    found.sort(key=lambda problem: problem[0].rank)
    return found


def _finding(
    ctx: ScanContext,
    region: str,
    group: dict[str, Any],
    tags: dict[str, str],
    problems: list[Problem],
) -> Finding:
    name = str(group.get("AutoScalingGroupName"))
    severity, title, _, _ = problems[0]
    evidence = [line for _, _, line, _ in problems]
    evidence.append(
        f"Desired capacity {group.get('DesiredCapacity')}, "
        f"between {group.get('MinSize')} and {group.get('MaxSize')}."
    )
    caveat = environment_caveat(tags)
    if caveat:
        evidence.append(caveat)

    steps = "; ".join(step for _, _, _, step in problems)
    return Finding(
        check="autoscaling-groups-that-cant-heal",
        module=MODULE,
        title=title,
        resource=Resource(
            id=name,
            kind="autoscaling:group",
            region=region,
            arn=group.get("AutoScalingGroupARN")
            or ctx.arn("autoscaling", region, f"autoScalingGroup:*:autoScalingGroupName/{name}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=(
            f"{steps[:1].upper()}{steps[1:]}. Then a failed instance is replaced "
            "without anyone having to notice it first."
        ),
        confidence=confidence_for(tags),
        severity=severity,
    )


AUTOSCALING_GROUPS_THAT_CANT_HEAL = Check(
    key="autoscaling-groups-that-cant-heal",
    title="Auto Scaling groups that can't heal",
    looks_for=(
        "Groups with replacement suspended, blind to their load balancer's health "
        "checks, or confined to one zone."
    ),
    actions=("autoscaling:DescribeAutoScalingGroups",),
    run=autoscaling_groups_that_cant_heal,
)
