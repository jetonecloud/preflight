"""Cost Check: what you're paying for that you aren't using."""

from __future__ import annotations

from preflight.modules.base import Module, ModuleStatus

COST = Module(
    key="cost",
    name="Cost Check",
    summary="Unattached volumes and IPs, idle NAT gateways and load balancers, "
    "stopped instances, old snapshots, oversized instances.",
    status=ModuleStatus.AVAILABLE,
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
