"""Security & IAM: the doors that are open, and who has keys to them.

Six checks, none priced: what a public bucket or a root user without MFA
costs is measured in incidents, not dollars a month. `identity` reads IAM -
the root user, console users, access keys - once, from the home region,
since IAM is global. `network` reads security groups and what's using them,
`storage` asks S3 which buckets are public, and `trail` asks whether
CloudTrail is recording any of it.

As with every module, `iam_actions` is exactly the union of what the checks
declare plus `support_actions`, and a test holds it to that.
"""

from __future__ import annotations

from preflight.modules.base import Module, ModuleStatus
from preflight.modules.security.identity import (
    CONSOLE_USERS_WITHOUT_MFA,
    ROOT_USER_UNGUARDED,
    STALE_ACCESS_KEYS,
)
from preflight.modules.security.network import OPEN_SECURITY_GROUPS
from preflight.modules.security.storage import PUBLIC_BUCKETS
from preflight.modules.security.trail import TRAIL_COVERAGE

#: Report order: whatever gets someone in fastest, first.
CHECKS = (
    ROOT_USER_UNGUARDED,
    PUBLIC_BUCKETS,
    OPEN_SECURITY_GROUPS,
    CONSOLE_USERS_WITHOUT_MFA,
    STALE_ACCESS_KEYS,
    TRAIL_COVERAGE,
)

#: Reads that belong to the scan rather than to a single check.
SUPPORT_ACTIONS = (
    # Which regions to look in. Without it we can only scan one.
    "ec2:DescribeRegions",
    # Tags for buckets and trails, whose own calls don't return them.
    "tag:GetResources",
)

SECURITY = Module(
    key="security",
    name="Security & IAM",
    summary="Root user and console MFA, stale access keys, public buckets, "
    "open security groups, CloudTrail.",
    status=ModuleStatus.AVAILABLE,
    checks=CHECKS,
    support_actions=SUPPORT_ACTIONS,
    iam_actions=(
        "ec2:DescribeRegions",
        # Who can sign in, and with what.
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListUserTags",
        # What the network lets in, and whether anything is behind it.
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        # Which buckets are public.
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        # Whether anything is writing it all down.
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        # Who owns it, and whether they've asked us to look away.
        "tag:GetResources",
    ),
)

__all__ = ["CHECKS", "SECURITY", "SUPPORT_ACTIONS"]
