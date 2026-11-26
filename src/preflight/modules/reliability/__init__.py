"""Reliability: what one failure would take down.

Five checks, none priced: a database with no standby costs nothing a month
until the hour it costs everything. `database` reads RDS - is there a
standby, and is there anything to restore from. `scaling` reads Auto
Scaling groups, `balancing` reads what's actually behind each load
balancer, and `containers` reads ECS services.

All of them believe an environment tag when there is one: anything tagged
dev, test or staging is allowed to fall over, and anything tagged production
is reported with high confidence. Untagged, a finding says it had to guess.

As with every module, `iam_actions` is exactly the union of what the checks
declare plus `support_actions`, and a test holds it to that.
"""

from __future__ import annotations

from preflight.modules.base import Module, ModuleStatus
from preflight.modules.reliability.balancing import FRAGILE_LOAD_BALANCED_SERVICES
from preflight.modules.reliability.containers import ECS_SERVICES_AT_RISK
from preflight.modules.reliability.database import (
    DATABASES_WITHOUT_BACKUPS,
    SINGLE_AZ_DATABASES,
)
from preflight.modules.reliability.scaling import AUTOSCALING_GROUPS_THAT_CANT_HEAL

#: Report order: what can't be got back first, then what's down, then what
#: would go down next.
CHECKS = (
    DATABASES_WITHOUT_BACKUPS,
    SINGLE_AZ_DATABASES,
    FRAGILE_LOAD_BALANCED_SERVICES,
    ECS_SERVICES_AT_RISK,
    AUTOSCALING_GROUPS_THAT_CANT_HEAL,
)

#: Reads that belong to the scan rather than to a single check.
SUPPORT_ACTIONS = (
    # Which regions to look in. Without it we can only scan one.
    "ec2:DescribeRegions",
    # Tags for load balancers and target groups, whose own calls don't
    # return them - which is how environment tags and `preflight:ignore`
    # reach them.
    "tag:GetResources",
)

RELIABILITY = Module(
    key="reliability",
    name="Reliability",
    summary="Databases with no standby or backups, load balancers one target from "
    "down, ECS services of one, Auto Scaling groups that can't heal.",
    status=ModuleStatus.AVAILABLE,
    checks=CHECKS,
    support_actions=SUPPORT_ACTIONS,
    iam_actions=(
        "ec2:DescribeRegions",
        # Databases: standbys, backups, snapshots.
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        # What replaces a failed instance.
        "autoscaling:DescribeAutoScalingGroups",
        # What's behind each load balancer, and where it runs.
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "ec2:DescribeInstances",
        # Containers.
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        # Who owns it, and whether they've asked us to look away.
        "tag:GetResources",
    ),
)

__all__ = ["CHECKS", "RELIABILITY", "SUPPORT_ACTIONS"]
