"""Observability: whether anyone would find out when something breaks.

Three checks, none of which put a dollar figure on anything: a log group
kept forever costs a little, but an alarm that pages nobody costs whatever
the outage it didn't tell you about costs. `logs` reads CloudWatch Logs;
`alarms` reads CloudWatch alarms and the SNS topics they publish to, and
the databases and load balancers they ought to be watching.

As with every module, `iam_actions` is exactly the union of what the checks
declare plus `support_actions`, and a test holds it to that.
"""

from __future__ import annotations

from preflight.modules.base import Module, ModuleStatus
from preflight.modules.observability.alarms import (
    ALARMS_THAT_NOTIFY_NOBODY,
    UNWATCHED_RESOURCES,
)
from preflight.modules.observability.logs import LOG_GROUPS_KEPT_FOREVER

#: Report order: the alarm nobody hears is the one that hurts.
CHECKS = (
    ALARMS_THAT_NOTIFY_NOBODY,
    UNWATCHED_RESOURCES,
    LOG_GROUPS_KEPT_FOREVER,
)

#: Reads that belong to the scan rather than to a single check.
SUPPORT_ACTIONS = (
    # Which regions to look in. Without it we can only scan one.
    "ec2:DescribeRegions",
    # Tags for alarms, topics, log groups and load balancers, whose own list
    # calls don't return them - which is how `preflight:ignore` reaches them.
    "tag:GetResources",
)

OBSERVABILITY = Module(
    key="observability",
    name="Observability",
    summary="Alarms that notify nobody, databases and load balancers with no alarm, "
    "log groups kept forever.",
    status=ModuleStatus.AVAILABLE,
    checks=CHECKS,
    support_actions=SUPPORT_ACTIONS,
    iam_actions=(
        "ec2:DescribeRegions",
        # The alarms, and where they send.
        "cloudwatch:DescribeAlarms",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        # What they ought to be watching.
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        # How long logs are kept.
        "logs:DescribeLogGroups",
        # Who owns it, and whether they've asked us to look away.
        "tag:GetResources",
    ),
)

__all__ = ["CHECKS", "OBSERVABILITY", "SUPPORT_ACTIONS"]
