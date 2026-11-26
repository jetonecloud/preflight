"""Modules that are declared but haven't shipped yet.

Their actions are real: between them and the shipped modules they account for every
action in `iam/policy.json`, which is the role you get with every module
selected. They live here rather than in their own files until their checks
are written - graduating one means moving it to `modules/<key>.py` and
flipping its status to `AVAILABLE`.
"""

from __future__ import annotations

from preflight.modules.base import Module

DELIVERY = Module(
    key="delivery",
    name="Delivery & IaC",
    summary="How much is managed as code, CloudFormation drift, deploy strategy, "
    "`latest` image tags, stale AMIs, SSH-only access.",
    iam_actions=(
        "cloudformation:ListStacks",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackDriftDetectionStatus",
        "cloudformation:DescribeStackResourceDrifts",
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ec2:DescribeImages",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeSecurityGroups",
        "codedeploy:ListApplications",
        "codedeploy:GetDeploymentConfig",
    ),
)

BUS_FACTOR = Module(
    key="bus-factor",
    name="Bus factor",
    summary="Whether changes come from one or two people, how many admins you have, "
    "resources with no clear owner.",
    iam_actions=(
        # Read-only event query. Listed as an exception to the Get/List/Describe
        # rule in core/iam.py - it reads the CloudTrail event history and
        # mutates nothing.
        "cloudtrail:LookupEvents",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "s3:GetBucketTagging",
        "tag:GetResources",
    ),
)
