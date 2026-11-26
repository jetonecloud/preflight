"""Load balancers, and what's actually behind them.

A load balancer makes a service look redundant from the outside whether or
not it is. What decides how many failures the service survives is the target
group: how many targets are registered, how many of them are passing their
health checks right now, and whether they're spread across zones or all
sitting in the same one.

Target groups an Auto Scaling group manages are left to the scaling check:
the group replaces what fails, so one target there is a capacity decision
rather than a single point of failure. Target groups with nothing registered
at all are the Cost Check's - that's waste, not fragility.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check
from preflight.modules.reliability.common import (
    MODULE,
    confidence_for,
    environment_caveat,
    non_production,
    too_new,
)

#: Target states that mean "registered and meant to be serving".
SERVING_STATES = frozenset({"healthy", "unhealthy", "initial", "unavailable"})


def fragile_load_balanced_services(ctx: ScanContext) -> Iterator[Finding]:
    """Target groups with nothing healthy, one lone instance, or one zone."""
    for region in ctx.regions:
        balancers = {
            str(balancer["LoadBalancerArn"]): balancer
            for balancer in ctx.collect(
                "elasticloadbalancing:DescribeLoadBalancers", "LoadBalancers", region=region
            )
            if balancer.get("LoadBalancerArn")
            and balancer.get("State", {}).get("Code") == "active"
            and balancer.get("Type") in ("application", "network")
        }
        if not balancers:
            continue

        groups = [
            group
            for group in ctx.collect(
                "elasticloadbalancing:DescribeTargetGroups", "TargetGroups", region=region
            )
            if any(arn in balancers for arn in group.get("LoadBalancerArns") or ())
            and group.get("TargetType", "instance") in ("instance", "ip")
        ]
        if not groups:
            continue

        managed = _scaled_target_groups(ctx, region)
        zones: dict[str, str] | None = None

        for group in groups:
            ctx.looked_at()
            arn = str(group.get("TargetGroupArn"))
            balancer = next(
                balancers[lb] for lb in group.get("LoadBalancerArns") or () if lb in balancers
            )
            tags = {
                **ctx.tags_for(region, str(balancer["LoadBalancerArn"])),
                **ctx.tags_for(region, arn),
            }
            if ignored(tags) or non_production(tags):
                continue
            if too_new(ctx, balancer.get("CreatedTime")):
                continue

            targets = [
                target
                for target in ctx.collect(
                    "elasticloadbalancing:DescribeTargetHealth",
                    "TargetHealthDescriptions",
                    region=region,
                    TargetGroupArn=arn,
                )
                if target.get("TargetHealth", {}).get("State") in SERVING_STATES
            ]
            if not targets:
                continue

            states = [str(target["TargetHealth"]["State"]) for target in targets]
            if all(state == "unhealthy" for state in states):
                yield _finding(
                    ctx,
                    region,
                    group,
                    balancer,
                    tags,
                    title="Load balancer with nothing healthy behind it",
                    what=(
                        f"All {len(targets)} registered target(s) are failing their "
                        "health checks right now."
                    ),
                    why=(
                        "Requests are either being refused or, with fail-open, sent "
                        "to targets the load balancer itself thinks are broken."
                    ),
                    fix=(
                        "Find out why the health check fails - the target's logs, "
                        "or the health check path and port against what the "
                        "service actually serves - before anything else."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                )
                continue

            if arn in managed:
                continue

            if len(targets) == 1:
                target = str(targets[0].get("Target", {}).get("Id"))
                yield _finding(
                    ctx,
                    region,
                    group,
                    balancer,
                    tags,
                    title="Load balancer with one target behind it",
                    what=f"{target} is the only registered target, and nothing replaces it.",
                    why=(
                        "When it fails, or is rebooted for patching, the service is "
                        "down: the load balancer has nowhere else to send anything."
                    ),
                    fix=(
                        "Run at least two targets in different Availability Zones - "
                        "ideally from an Auto Scaling group, so a failed one is "
                        "replaced without anyone doing it."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=confidence_for(tags),
                )
                continue

            if zones is None:
                zones = _instance_zones(ctx, region)
            placed = {_zone_of(target, zones) for target in targets}
            if len(placed) == 1 and None not in placed:
                (zone,) = placed
                yield _finding(
                    ctx,
                    region,
                    group,
                    balancer,
                    tags,
                    title="Load balancer whose targets share one zone",
                    what=f"All {len(targets)} targets are in {zone}.",
                    why=(
                        "They'll fail together: a zone outage takes the whole "
                        "service with it, however many targets there are."
                    ),
                    fix="Move at least one target into another Availability Zone.",
                    severity=Severity.MEDIUM,
                    confidence=confidence_for(tags),
                )


def _scaled_target_groups(ctx: ScanContext, region: str) -> set[str]:
    """Target groups an Auto Scaling group registers its instances in."""
    return {
        str(arn)
        for group in ctx.collect(
            "autoscaling:DescribeAutoScalingGroups", "AutoScalingGroups", region=region
        )
        for arn in group.get("TargetGroupARNs") or ()
    }


def _instance_zones(ctx: ScanContext, region: str) -> dict[str, str]:
    """Instance ID -> Availability Zone, for every instance in the region."""
    return {
        str(instance.get("InstanceId")): str(instance.get("Placement", {}).get("AvailabilityZone"))
        for reservation in ctx.collect("ec2:DescribeInstances", "Reservations", region=region)
        for instance in reservation.get("Instances") or ()
        if instance.get("Placement", {}).get("AvailabilityZone")
    }


def _zone_of(target: dict[str, Any], zones: dict[str, str]) -> str | None:
    """Where a target runs, if anything says - `all` means it isn't pinned."""
    described = target.get("Target", {})
    zone = described.get("AvailabilityZone") or zones.get(str(described.get("Id")))
    return None if zone in (None, "all") else str(zone)


def _finding(
    ctx: ScanContext,
    region: str,
    group: dict[str, Any],
    balancer: dict[str, Any],
    tags: dict[str, str],
    *,
    title: str,
    what: str,
    why: str,
    fix: str,
    severity: Severity,
    confidence: Confidence,
) -> Finding:
    name = str(group.get("TargetGroupName"))
    evidence = [
        f"Target group {name}, behind {balancer.get('LoadBalancerName')}.",
        what,
        why,
    ]
    caveat = environment_caveat(tags)
    if caveat and confidence is not Confidence.HIGH:
        evidence.append(caveat)
    return Finding(
        check="fragile-load-balanced-services",
        module=MODULE,
        title=title,
        resource=Resource(
            id=name,
            kind="elb:target-group",
            region=region,
            arn=str(group.get("TargetGroupArn")),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=fix,
        confidence=confidence,
        severity=severity,
    )


FRAGILE_LOAD_BALANCED_SERVICES = Check(
    key="fragile-load-balanced-services",
    title="Load-balanced services one failure from down",
    looks_for=(
        "Target groups with nothing healthy, a single target nothing replaces, "
        "or every target in one zone."
    ),
    actions=(
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "autoscaling:DescribeAutoScalingGroups",
        "ec2:DescribeInstances",
    ),
    run=fragile_load_balanced_services,
)
