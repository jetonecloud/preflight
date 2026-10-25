"""Networking you're renting by the hour and nothing is going through.

The three in here are the classic ones. An Elastic IP nobody attached is
small and annoying; a NAT gateway left behind by a deleted environment is
$33 a month forever; a load balancer with no targets is $16 a month to
return 503s.

All three lean on CloudWatch, so all three take the same care: no datapoints
is not the same as zero traffic, and a resource younger than the window
hasn't had a chance to show us anything.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

from preflight.core.findings import (
    Confidence,
    Estimate,
    Finding,
    Resource,
    Severity,
    at_least,
)
from preflight.core.metrics import DAY, MetricRequest, MetricSeries
from preflight.core.pricing import LOAD_BALANCER_HOUR, NAT_GATEWAY_HOUR, PUBLIC_IPV4_HOUR
from preflight.core.scan import ScanContext, ignored, name_of, tags_to_dict
from preflight.modules.base import Check

MODULE = "cost"

#: A resource has to have existed for the whole lookback window before its
#: metrics mean anything. One created on Tuesday has a quiet fortnight
#: behind it for the most innocent reason there is.
MIN_AGE_FOR_METRICS_DAYS = 2


# --- Elastic IPs ----------------------------------------------------------


def unassociated_ips(ctx: ScanContext) -> Iterator[Finding]:
    """Public IPv4 addresses allocated to the account and attached to nothing."""
    for region in ctx.regions:
        for address in ctx.collect("ec2:DescribeAddresses", "Addresses", region=region):
            ctx.looked_at()
            tags = tags_to_dict(address.get("Tags"))
            if ignored(tags):
                continue
            if address.get("AssociationId") or address.get("InstanceId"):
                continue
            if address.get("NetworkInterfaceId"):
                continue

            # Addresses you brought yourself aren't billed at the Amazon rate,
            # so we'd be quoting a number that isn't on anyone's invoice.
            pool = str(address.get("PublicIpv4Pool") or "amazon")
            if pool != "amazon" or address.get("CustomerOwnedIp"):
                continue

            allocation_id = str(address.get("AllocationId") or address.get("PublicIp"))
            public_ip = str(address.get("PublicIp") or allocation_id)
            monthly = PUBLIC_IPV4_HOUR.monthly()

            yield Finding(
                check="unassociated-public-ips",
                module=MODULE,
                title=f"Elastic IP {public_ip} isn't attached to anything",
                resource=Resource(
                    id=allocation_id,
                    kind="ec2:elastic-ip",
                    region=region,
                    name=name_of(tags),
                    arn=ctx.arn("ec2", region, f"elastic-ip/{allocation_id}"),
                    tags=tags,
                ),
                evidence=(
                    "No instance, network interface or association is using it.",
                    "AWS charges for every public IPv4 address it has allocated to "
                    "you, whether or not anything is behind it.",
                    PUBLIC_IPV4_HOUR.describe(1, "address"),
                ),
                recommendation=(
                    "Release it. If it's being held because the address itself "
                    "matters — an allowlist somewhere, a DNS record you can't "
                    "change yet — tag it 'preflight:ignore'."
                ),
                confidence=Confidence.HIGH,
                estimate=Estimate(monthly, PUBLIC_IPV4_HOUR.describe(1, "address")),
            )


# --- NAT gateways ---------------------------------------------------------


def idle_nat_gateways(ctx: ScanContext) -> Iterator[Finding]:
    """NAT gateways with no bytes and no connections over the whole window."""
    for region in ctx.regions:
        gateways = [
            gateway
            for gateway in ctx.collect("ec2:DescribeNatGateways", "NatGateways", region=region)
            if gateway.get("State") == "available"
        ]
        ctx.looked_at(len(gateways))
        candidates = [
            gateway
            for gateway in gateways
            if not ignored(tags_to_dict(gateway.get("Tags")))
            and _old_enough(ctx, gateway.get("CreateTime"))
        ]
        if not candidates:
            continue

        requests = []
        for gateway in candidates:
            gateway_id = str(gateway["NatGatewayId"])
            requests.append(
                MetricRequest(
                    key=f"{gateway_id}/bytes",
                    namespace="AWS/NATGateway",
                    metric="BytesOutToDestination",
                    dimensions={"NatGatewayId": gateway_id},
                    statistics=("Sum",),
                    period=DAY,
                )
            )
            requests.append(
                MetricRequest(
                    key=f"{gateway_id}/connections",
                    namespace="AWS/NATGateway",
                    metric="ActiveConnectionCount",
                    dimensions={"NatGatewayId": gateway_id},
                    statistics=("Maximum",),
                    period=DAY,
                )
            )
        series = ctx.metrics(region, requests)

        for gateway in candidates:
            gateway_id = str(gateway["NatGatewayId"])
            traffic = series.get(f"{gateway_id}/bytes", MetricSeries(gateway_id))
            connections = series.get(f"{gateway_id}/connections", MetricSeries(gateway_id))

            bytes_out = traffic.total("Sum") or 0.0
            peak_connections = connections.maximum("Maximum") or 0.0
            if bytes_out > 0 or peak_connections > 0:
                continue

            tags = tags_to_dict(gateway.get("Tags"))
            monthly = NAT_GATEWAY_HOUR.monthly()
            basis = NAT_GATEWAY_HOUR.describe(1, "NAT gateway")
            age = ctx.days_since(gateway.get("CreateTime"))

            evidence = [
                f"No bytes left this gateway in the last {ctx.lookback_days} days.",
                "Peak active connections over the same window: 0.",
            ]
            if not traffic.has_data:
                evidence.append(
                    "CloudWatch has no datapoints for it at all, which is what an "
                    "unused gateway looks like."
                )
            if age is not None:
                evidence.append(f"Created {age:,.0f} days ago in subnet {gateway.get('SubnetId')}.")
            evidence.append(
                "NAT gateways bill by the hour from the moment they exist, "
                "separately from the per-GB data charge."
            )

            yield Finding(
                check="idle-nat-gateways",
                module=MODULE,
                title="NAT gateway with no traffic",
                resource=Resource(
                    id=gateway_id,
                    kind="ec2:nat-gateway",
                    region=region,
                    name=name_of(tags),
                    arn=ctx.arn("ec2", region, f"natgateway/{gateway_id}"),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "If the private subnets behind it no longer need outbound "
                    "internet, delete the gateway and its routes. If they only "
                    "talk to AWS services, a VPC endpoint does the same job "
                    "without the hourly charge."
                ),
                confidence=Confidence.MEDIUM,
                estimate=Estimate(monthly, basis),
            )


# --- Load balancers -------------------------------------------------------


def idle_load_balancers(ctx: ScanContext) -> Iterator[Finding]:
    """Load balancers with nothing registered behind them, or no requests at all."""
    for region in ctx.regions:
        yield from _idle_v2_balancers(ctx, region)
        yield from _idle_classic_balancers(ctx, region)


def _idle_v2_balancers(ctx: ScanContext, region: str) -> Iterator[Finding]:
    balancers = [
        balancer
        for balancer in ctx.collect(
            "elasticloadbalancing:DescribeLoadBalancers", "LoadBalancers", region=region
        )
        if balancer.get("State", {}).get("Code") == "active"
    ]
    ctx.looked_at(len(balancers))
    if not balancers:
        return

    groups = ctx.collect("elasticloadbalancing:DescribeTargetGroups", "TargetGroups", region=region)
    by_balancer: dict[str, list[dict[str, Any]]] = {}
    for group in groups:
        for arn in group.get("LoadBalancerArns", ()):
            by_balancer.setdefault(str(arn), []).append(group)

    for balancer in balancers:
        arn = str(balancer["LoadBalancerArn"])
        kind = str(balancer.get("Type") or "application")
        name = str(balancer.get("LoadBalancerName") or arn.rsplit("/", 1)[-1])
        tags = dict(ctx.tags_for(region, arn))
        if ignored(tags):
            continue

        attached = by_balancer.get(arn, [])
        registered = _registered_targets(ctx, region, attached)

        reason: str | None = None
        confidence = Confidence.HIGH
        if not attached:
            reason = "It has no target groups attached, so nothing can be behind it."
        elif registered == 0:
            reason = (
                f"Its {len(attached)} target group(s) have no registered targets, "
                "so every request to it fails."
            )
        elif _old_enough(ctx, balancer.get("CreatedTime")):
            traffic = _v2_traffic(ctx, region, kind, arn)
            if traffic is not None and traffic == 0:
                reason = (
                    f"{registered} target(s) registered, but no requests reached it "
                    f"in the last {ctx.lookback_days} days."
                )
                confidence = Confidence.MEDIUM

        if reason is None:
            continue

        price = LOAD_BALANCER_HOUR.get(kind, LOAD_BALANCER_HOUR["application"])
        basis = price.describe(1, f"{kind} load balancer")
        created = ctx.days_since(balancer.get("CreatedTime"))
        when = f"{created:,.0f} days ago" if created is not None else "at an unknown time"
        evidence = [reason, f"{kind.title()} load balancer in {region}, created {when}."]
        evidence.append(
            "Load balancers bill by the hour plus capacity units; only the hourly "
            "part is counted here, so the real saving is a little higher."
        )

        yield Finding(
            check="idle-load-balancers",
            module=MODULE,
            title=f"{kind.title()} load balancer with nothing behind it",
            resource=Resource(
                id=name,
                kind=f"elb:{kind}",
                region=region,
                name=name_of(tags),
                arn=arn,
                tags=tags,
            ),
            evidence=tuple(evidence),
            recommendation=(
                "Delete it along with its listeners and target groups. If it's "
                "a placeholder for something that hasn't launched yet, tag it "
                "'preflight:ignore' until it has."
            ),
            confidence=confidence,
            estimate=Estimate(price.monthly(), basis),
        )


def _registered_targets(ctx: ScanContext, region: str, groups: Sequence[dict[str, Any]]) -> int:
    total = 0
    for group in groups:
        health = ctx.collect(
            "elasticloadbalancing:DescribeTargetHealth",
            "TargetHealthDescriptions",
            region=region,
            TargetGroupArn=str(group["TargetGroupArn"]),
        )
        total += len(health)
    return total


def _v2_traffic(ctx: ScanContext, region: str, kind: str, arn: str) -> float | None:
    """Requests (ALB) or new flows (NLB) over the window, or `None` if unknown."""
    dimension = arn.split("loadbalancer/", 1)[-1]
    if kind == "application":
        namespace, metric = "AWS/ApplicationELB", "RequestCount"
    elif kind == "network":
        namespace, metric = "AWS/NetworkELB", "NewFlowCount"
    else:
        # Gateway load balancers don't publish a comparable counter, so we
        # only ever flag those on having no targets.
        return None
    series = ctx.metrics(
        region,
        [
            MetricRequest(
                key=arn,
                namespace=namespace,
                metric=metric,
                dimensions={"LoadBalancer": dimension},
                statistics=("Sum",),
                period=DAY,
            )
        ],
    ).get(arn)
    if series is None or not series.has_data:
        return None
    return series.total("Sum") or 0.0


def _idle_classic_balancers(ctx: ScanContext, region: str) -> Iterator[Finding]:
    """Classic load balancers, which are usually the oldest thing in an account."""
    balancers = ctx.collect(
        "elasticloadbalancing:DescribeLoadBalancers",
        "LoadBalancerDescriptions",
        region=region,
        client="elb",
    )
    ctx.looked_at(len(balancers))
    for balancer in balancers:
        name = str(balancer.get("LoadBalancerName") or "")
        if not name:
            continue
        arn = ctx.arn("elasticloadbalancing", region, f"loadbalancer/{name}")
        tags = dict(ctx.tags_for(region, arn))
        if ignored(tags):
            continue

        instances = balancer.get("Instances", ())
        if instances:
            continue

        price = LOAD_BALANCER_HOUR["classic"]
        created = ctx.days_since(balancer.get("CreatedTime"))
        evidence = [
            "No instances are registered with it, so every request to it fails.",
            "This is a Classic load balancer — the previous generation, which AWS "
            "has been encouraging people off for years.",
        ]
        if created is not None:
            evidence.append(f"Created {created:,.0f} days ago.")

        yield Finding(
            check="idle-load-balancers",
            module=MODULE,
            title="Classic load balancer with no instances",
            resource=Resource(
                id=name,
                kind="elb:classic",
                region=region,
                name=name_of(tags),
                arn=arn,
                tags=tags,
            ),
            evidence=tuple(evidence),
            recommendation=(
                "Delete it. If something still points at its DNS name, move that "
                "to an Application load balancer first."
            ),
            confidence=Confidence.HIGH,
            estimate=Estimate(price.monthly(), price.describe(1, "Classic load balancer")),
            # The $18 is the small half of this one: it's also a dependency on
            # a load balancer generation that's been on the way out for years.
            severity=at_least(Severity.MEDIUM, price.monthly()),
        )


def _old_enough(ctx: ScanContext, created: Any) -> bool:
    """Whether a resource has existed long enough for its metrics to mean anything."""
    age = ctx.days_since(created)
    if age is None:
        return True
    return age >= max(ctx.lookback_days, MIN_AGE_FOR_METRICS_DAYS)


UNASSOCIATED_IPS = Check(
    key="unassociated-public-ips",
    title="Elastic IPs attached to nothing",
    looks_for="Public IPv4 addresses you're renting that aren't pointed at anything.",
    actions=("ec2:DescribeAddresses",),
    run=unassociated_ips,
)

IDLE_NAT_GATEWAYS = Check(
    key="idle-nat-gateways",
    title="NAT gateways with no traffic",
    looks_for="NAT gateways billing $30+ a month with nothing routing through them.",
    actions=("ec2:DescribeNatGateways", "cloudwatch:GetMetricStatistics"),
    run=idle_nat_gateways,
)

IDLE_LOAD_BALANCERS = Check(
    key="idle-load-balancers",
    title="Load balancers with nothing behind them",
    looks_for="Load balancers with no targets registered, or no requests at all.",
    actions=(
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "cloudwatch:GetMetricStatistics",
    ),
    run=idle_load_balancers,
)
