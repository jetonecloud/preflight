"""Instances that cost more than the work they're doing.

Two different shapes of waste. A stopped instance isn't billed for compute
at all — the money is in the disks nobody deleted with it, which is worth
saying plainly because "stopped instances cost nothing" is the thing most
people half-remember. An oversized instance is billed in full for capacity
it never touches.

The second one is the easiest check in this module to get wrong. CPU is a
proxy, not a measurement of usefulness: a memory-bound service, a queue
worker that's quiet on weekends, and a box that exists purely for its
network throughput all look identical to `CPUUtilization`. So the guards
here are deliberately heavy, and the recommendation says what to confirm
before acting rather than pretending the check already did.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Estimate, Finding, Resource
from preflight.core.metrics import DAY, HOUR, MetricRequest, window_periods
from preflight.core.pricing import HOURS_PER_MONTH, ebs_monthly, smaller_sizes
from preflight.core.scan import ScanContext, ignored, name_of, tags_to_dict
from preflight.modules.base import Check

MODULE = "cost"

#: Below this, a stopped instance is just a stopped instance — someone is
#: working on it this sprint.
STOPPED_DAYS = 30

#: Peak CPU over the whole window, as a percentage. "Peak", not average: an
#: instance that hits 80% once a day is sized for that spike, and averaging
#: it away is how you end up recommending an outage.
BUSY_CPU_PERCENT = 10.0

#: How much of the window has to have datapoints before the CPU reading is
#: worth anything. An instance CloudWatch barely saw isn't evidence.
MIN_METRIC_COVERAGE = 0.5

#: Daily inbound bytes above which we leave an instance alone whatever its
#: CPU says. Network throughput is capped by instance size, so a quiet-CPU
#: box moving real traffic is not a safe thing to shrink. 50 GB/day.
BUSY_NETWORK_BYTES_PER_DAY = 50 * 1024**3

#: `User initiated (2025-08-02 14:33:21 GMT)` — the only record EC2 keeps of
#: when an instance stopped.
STOP_TIME = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")


def long_stopped_instances(ctx: ScanContext) -> Iterator[Finding]:
    """Instances stopped for a month or more, still paying for their disks."""
    for region in ctx.regions:
        instances = _instances(ctx, region, states=("stopped",))
        if not instances:
            continue
        managed = _asg_instance_ids(ctx, region)
        volumes = _volumes_by_instance(ctx, region)

        for instance in instances:
            ctx.looked_at()
            instance_id = str(instance["InstanceId"])
            tags = tags_to_dict(instance.get("Tags"))
            if ignored(tags) or instance_id in managed:
                continue

            stopped_at = _stopped_at(instance)
            days = ctx.days_since(stopped_at)
            if days is None or days < STOPPED_DAYS:
                continue

            attached = volumes.get(instance_id, [])
            monthly = 0.0
            lines: list[str] = []
            for volume in attached:
                size = float(volume.get("Size") or 0)
                volume_type = str(volume.get("VolumeType") or "standard")
                amount, line = ebs_monthly(volume_type, size)
                monthly += amount
                lines.append(line)
            if monthly <= 0:
                continue

            total_gb = sum(float(volume.get("Size") or 0) for volume in attached)
            basis = (
                lines[0]
                if len(lines) == 1
                else f"{len(lines)} attached volumes, {total_gb:,.0f} GB in total: "
                + " ".join(lines)
            )
            evidence = [
                f"Stopped {days:,.0f} days ago and not started since.",
                f"Still has {len(attached)} volume(s) attached, {total_gb:,.0f} GB in total.",
                "A stopped instance isn't charged for compute, but its EBS volumes "
                "are billed exactly as if it were running.",
                f"Instance type {instance.get('InstanceType')}, in {region}.",
            ]

            yield Finding(
                check="long-stopped-instances",
                module=MODULE,
                title=f"Instance stopped for {days:,.0f} days, still paying for its disks",
                resource=Resource(
                    id=instance_id,
                    kind="ec2:instance",
                    region=region,
                    name=name_of(tags),
                    arn=ctx.arn("ec2", region, f"instance/{instance_id}"),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "If you'd miss it, create an AMI and terminate the instance — "
                    "the image costs a fraction of the live volumes and you can "
                    "launch it back. If you wouldn't, terminate it."
                ),
                confidence=Confidence.HIGH,
                estimate=Estimate(monthly, basis),
            )


def oversized_instances(ctx: ScanContext) -> Iterator[Finding]:
    """Running instances whose CPU never gets near what they're sized for."""
    for region in ctx.regions:
        instances = [
            instance
            for instance in _instances(ctx, region, states=("running",))
            if _resizable(ctx, instance)
        ]
        ctx.looked_at(len(instances))
        if not instances:
            continue

        managed = _asg_instance_ids(ctx, region)
        # CloudWatch returns at most 1440 datapoints per call, so an hourly
        # period runs out somewhere past two months. `window_periods` drops
        # to daily before that happens; the peak of a day's maxima is still
        # a peak, so the judgement doesn't change with it.
        period = window_periods(ctx.lookback_days)
        requests = []
        for instance in instances:
            instance_id = str(instance["InstanceId"])
            requests.append(
                MetricRequest(
                    key=f"{instance_id}/cpu",
                    namespace="AWS/EC2",
                    metric="CPUUtilization",
                    dimensions={"InstanceId": instance_id},
                    statistics=("Maximum", "Average"),
                    period=period,
                    unit="Percent",
                )
            )
            requests.append(
                MetricRequest(
                    key=f"{instance_id}/net",
                    namespace="AWS/EC2",
                    metric="NetworkIn",
                    dimensions={"InstanceId": instance_id},
                    statistics=("Sum",),
                    period=DAY,
                    unit="Bytes",
                )
            )
        series = ctx.metrics(region, requests)
        expected = ctx.lookback_days * (24 if period == HOUR else 1)

        for instance in instances:
            instance_id = str(instance["InstanceId"])
            cpu = series.get(f"{instance_id}/cpu")
            network = series.get(f"{instance_id}/net")
            if cpu is None or not cpu.has_data or cpu.count < expected * MIN_METRIC_COVERAGE:
                continue

            peak = cpu.maximum("Maximum")
            if peak is None or peak >= BUSY_CPU_PERCENT:
                continue

            daily_bytes = _daily_average(network)
            if daily_bytes is not None and daily_bytes > BUSY_NETWORK_BYTES_PER_DAY:
                continue

            instance_type = str(instance.get("InstanceType") or "")
            current_rate = ctx.prices.hourly(region, instance_type)
            if current_rate is None:
                continue
            smaller, smaller_rate = _next_size_down(ctx, region, instance_type, current_rate)
            if smaller is None or smaller_rate is None:
                continue

            monthly = (current_rate - smaller_rate) * HOURS_PER_MONTH
            basis = (
                f"{instance_type} at ${current_rate:.4f}/hour versus {smaller} at "
                f"${smaller_rate:.4f}/hour, over {HOURS_PER_MONTH} hours "
                f"({'live pricing API' if ctx.prices.used_api else 'built-in price table'}, "
                "on-demand Linux, no Savings Plan applied)."
            )

            tags = tags_to_dict(instance.get("Tags"))
            average = cpu.average("Average")
            evidence = [
                f"Peak CPU over the last {ctx.lookback_days} days was {peak:.1f}%, "
                f"against a {BUSY_CPU_PERCENT:.0f}% bar.",
                f"Based on {cpu.count} hourly datapoints.",
            ]
            if average is not None:
                evidence.append(f"Average CPU across the window: {average:.1f}%.")
            if daily_bytes is not None:
                evidence.append(f"Inbound network averaged {_gb(daily_bytes)} a day.")
            if instance_id in managed:
                evidence.append(
                    "This instance belongs to an Auto Scaling group, so its size "
                    "comes from a launch template rather than the instance itself."
                )
            evidence.append(
                "CPU is only part of the picture — check memory and disk before resizing anything."
            )

            yield Finding(
                check="oversized-instances",
                module=MODULE,
                title=f"{instance_type} running at under {BUSY_CPU_PERCENT:.0f}% CPU",
                resource=Resource(
                    id=instance_id,
                    kind="ec2:instance",
                    region=region,
                    name=name_of(tags),
                    arn=ctx.arn("ec2", region, f"instance/{instance_id}"),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    f"Check memory and disk usage, then try {smaller}. "
                    + (
                        "Change it in the Auto Scaling group's launch template and "
                        "let the group replace the instance."
                        if instance_id in managed
                        else "Resizing needs a stop and start, so do it in a window."
                    )
                ),
                confidence=Confidence.MEDIUM,
                estimate=Estimate(monthly, basis),
            )


# --- shared reads ---------------------------------------------------------


def _instances(ctx: ScanContext, region: str, *, states: tuple[str, ...]) -> list[dict[str, Any]]:
    """Flatten `DescribeInstances` reservations into instances."""
    reservations = ctx.collect(
        "ec2:DescribeInstances",
        "Reservations",
        region=region,
        Filters=[{"Name": "instance-state-name", "Values": list(states)}],
    )
    return [
        instance for reservation in reservations for instance in reservation.get("Instances", ())
    ]


def _volumes_by_instance(ctx: ScanContext, region: str) -> dict[str, list[dict[str, Any]]]:
    """Every attached volume, keyed by the instance it's attached to."""
    by_instance: dict[str, list[dict[str, Any]]] = {}
    for volume in ctx.collect("ec2:DescribeVolumes", "Volumes", region=region):
        for attachment in volume.get("Attachments", ()):
            instance_id = attachment.get("InstanceId")
            if instance_id:
                by_instance.setdefault(str(instance_id), []).append(volume)
    return by_instance


def _asg_instance_ids(ctx: ScanContext, region: str) -> set[str]:
    """Instances currently managed by an Auto Scaling group.

    Asked of the Auto Scaling API rather than read off the instance's
    `aws:autoscaling:groupName` tag, because that tag can be removed and the
    answer still needs to be right.
    """
    managed: set[str] = set()
    for group in ctx.collect(
        "autoscaling:DescribeAutoScalingGroups", "AutoScalingGroups", region=region
    ):
        for instance in group.get("Instances", ()):
            if instance.get("InstanceId"):
                managed.add(str(instance["InstanceId"]))
    return managed


def _resizable(ctx: ScanContext, instance: dict[str, Any]) -> bool:
    """Whether it makes sense to talk about this instance's size at all."""
    tags = tags_to_dict(instance.get("Tags"))
    if ignored(tags):
        return False
    # Spot capacity is priced separately and can vanish anyway; dedicated
    # hosts and reservations have their own economics we can't see from here.
    if instance.get("InstanceLifecycle") == "spot":
        return False
    if instance.get("Placement", {}).get("Tenancy") not in (None, "default"):
        return False
    age = ctx.days_since(instance.get("LaunchTime"))
    return age is None or age >= ctx.lookback_days


def _next_size_down(
    ctx: ScanContext, region: str, instance_type: str, current_rate: float
) -> tuple[str | None, float | None]:
    """The nearest smaller size we can actually put a price on.

    Sizes that don't exist in a family have no price, which is how they get
    skipped without needing a table of which family has which rungs.
    """
    for candidate in smaller_sizes(instance_type):
        rate = ctx.prices.hourly(region, candidate)
        if rate is not None and rate < current_rate:
            return candidate, rate
    return None, None


def _stopped_at(instance: dict[str, Any]) -> str | None:
    """When EC2 says the instance stopped, if it said."""
    match = STOP_TIME.search(str(instance.get("StateTransitionReason") or ""))
    return f"{match.group(1)}+00:00" if match else None


def _daily_average(series: Any) -> float | None:
    if series is None or not series.has_data:
        return None
    total = series.total("Sum")
    return None if total is None else total / max(series.count, 1)


def _gb(value: float) -> str:
    return f"{value / 1024**3:,.1f} GB"


LONG_STOPPED_INSTANCES = Check(
    key="long-stopped-instances",
    title="Instances stopped for a month or more",
    looks_for="Stopped instances whose EBS volumes are still on the bill.",
    actions=(
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "autoscaling:DescribeAutoScalingGroups",
    ),
    run=long_stopped_instances,
)

OVERSIZED_INSTANCES = Check(
    key="oversized-instances",
    title="Instances bigger than their workload",
    looks_for="Running instances whose peak CPU never approaches what they're paying for.",
    actions=(
        "ec2:DescribeInstances",
        "autoscaling:DescribeAutoScalingGroups",
        "cloudwatch:GetMetricStatistics",
        "pricing:GetProducts",
    ),
    run=oversized_instances,
)
