"""Delivery: whether what's running is what was deployed, and could be again.

Three checks, none priced. `stacks` reads CloudFormation - stacks stuck
after a failed deploy, and stacks whose last drift detection found hand
edits. `images` reads ECS task definitions for containers that run
whatever `:latest` points at today. `amis` reads the images running
instances were launched from, for ones that are gone or a year stale.

As with every module, `iam_actions` is exactly the union of what the checks
declare plus `support_actions`, and a test holds it to that.
"""

from __future__ import annotations

from preflight.modules.base import Module, ModuleStatus
from preflight.modules.delivery.amis import INSTANCES_YOU_COULDNT_REBUILD
from preflight.modules.delivery.images import SERVICES_ON_MOVING_TAGS
from preflight.modules.delivery.stacks import CLOUDFORMATION_STACKS_AT_RISK

#: Report order: what blocks the next deploy first, then what the next
#: restart might change, then what couldn't be rebuilt at all.
CHECKS = (
    CLOUDFORMATION_STACKS_AT_RISK,
    SERVICES_ON_MOVING_TAGS,
    INSTANCES_YOU_COULDNT_REBUILD,
)

#: Reads that belong to the scan rather than to a single check.
SUPPORT_ACTIONS = (
    # Which regions to look in. Without it we can only scan one.
    "ec2:DescribeRegions",
)

DELIVERY = Module(
    key="delivery",
    name="Delivery & IaC",
    summary="CloudFormation stacks stuck or drifted, services deploying :latest, "
    "instances launched from an image that's gone or a year old.",
    status=ModuleStatus.AVAILABLE,
    checks=CHECKS,
    support_actions=SUPPORT_ACTIONS,
    iam_actions=(
        "ec2:DescribeRegions",
        # Infrastructure as code: stuck stacks and what's drifted.
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResourceDrifts",
        # What each service actually runs, and whether its tags can move.
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecr:DescribeRepositories",
        # What each instance was launched from.
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
    ),
)

__all__ = ["CHECKS", "DELIVERY", "SUPPORT_ACTIONS"]
