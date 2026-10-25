"""Cost Check: what you're paying for that you aren't using.

Nine checks, grouped by what they read rather than by what they find:
`storage` for EBS, `network` for the things billed by the hour for existing,
`compute` for EC2 and `database` for RDS.

The module's `iam_actions` is the union of what those checks declare plus
`support_actions` — the reads that belong to the scan rather than to any one
check. A test enforces that, so the role Preflight generates stays exactly
the set of calls Preflight makes.
"""

from __future__ import annotations

from preflight.modules.base import Module, ModuleStatus
from preflight.modules.cost.compute import LONG_STOPPED_INSTANCES, OVERSIZED_INSTANCES
from preflight.modules.cost.database import OLD_DATABASE_SNAPSHOTS, STOPPED_DATABASES
from preflight.modules.cost.network import (
    IDLE_LOAD_BALANCERS,
    IDLE_NAT_GATEWAYS,
    UNASSOCIATED_IPS,
)
from preflight.modules.cost.storage import OLD_SNAPSHOTS, UNATTACHED_VOLUMES

#: Report order: cheapest to act on first. Someone reading this on a Friday
#: should be able to do the first two before they go home.
CHECKS = (
    UNATTACHED_VOLUMES,
    UNASSOCIATED_IPS,
    IDLE_NAT_GATEWAYS,
    IDLE_LOAD_BALANCERS,
    LONG_STOPPED_INSTANCES,
    STOPPED_DATABASES,
    OLD_SNAPSHOTS,
    OLD_DATABASE_SNAPSHOTS,
    OVERSIZED_INSTANCES,
)

#: Reads that belong to the scan rather than to a single check.
SUPPORT_ACTIONS = (
    # Which regions to look in. Without it we can only scan one.
    "ec2:DescribeRegions",
    # Last month's bill, so the report can say what the findings are worth
    # relative to it. Optional: denied means the comparison is left out.
    "ce:GetCostAndUsage",
    # Owner tags for resources whose own API doesn't return them, which is
    # how a finding gets a name next to it instead of just an ARN.
    "tag:GetResources",
)

COST = Module(
    key="cost",
    name="Cost Check",
    summary="Unattached volumes and IPs, idle NAT gateways and load balancers, "
    "stopped instances, old snapshots, oversized instances.",
    status=ModuleStatus.AVAILABLE,
    checks=CHECKS,
    support_actions=SUPPORT_ACTIONS,
    iam_actions=(
        # What exists, and how big it is.
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeAddresses",
        "ec2:DescribeSnapshots",
        "ec2:DescribeNatGateways",
        "ec2:DescribeImages",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "autoscaling:DescribeAutoScalingGroups",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        # Whether it's actually being used.
        "cloudwatch:GetMetricStatistics",
        # What it costs, and what the alternatives cost.
        "ce:GetCostAndUsage",
        "pricing:GetProducts",
        # Who owns it.
        "tag:GetResources",
    ),
)

__all__ = ["CHECKS", "COST", "SUPPORT_ACTIONS"]
