"""Modules that are declared but haven't shipped yet.

Their actions are real: between them and `cost.py` they account for every
action in `iam/policy.json`, which is the role you get with every module
selected. They live here rather than in their own files until their checks
are written — graduating one means moving it to `modules/<key>.py` and
flipping its status to `AVAILABLE`.
"""

from __future__ import annotations

from preflight.modules.base import Module

SECURITY = Module(
    key="security",
    name="Security & IAM",
    summary="MFA, stale access keys, root account usage, public buckets, "
    "open security groups, CloudTrail, encryption defaults.",
    iam_actions=(
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:ListRoles",
        "iam:ListPolicies",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
    ),
)

RELIABILITY = Module(
    key="reliability",
    name="Reliability",
    summary="Single-AZ databases, missing backups, no autoscaling, missing health checks.",
    iam_actions=(
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "autoscaling:DescribeAutoScalingGroups",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeClusters",
        "ecs:DescribeServices",
    ),
)

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

OBSERVABILITY = Module(
    key="observability",
    name="Observability",
    summary="Alarm coverage, log retention, where alerts actually go.",
    iam_actions=(
        "cloudwatch:DescribeAlarms",
        "logs:DescribeLogGroups",
        "sns:ListTopics",
        "sns:ListSubscriptions",
    ),
)

BUS_FACTOR = Module(
    key="bus-factor",
    name="Bus factor",
    summary="Whether changes come from one or two people, how many admins you have, "
    "resources with no clear owner.",
    iam_actions=(
        # Read-only event query. Listed as an exception to the Get/List/Describe
        # rule in core/iam.py — it reads the CloudTrail event history and
        # mutates nothing.
        "cloudtrail:LookupEvents",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "s3:GetBucketTagging",
        "tag:GetResources",
    ),
)
