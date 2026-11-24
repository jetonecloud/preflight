"""S3 buckets anyone on the internet can read.

S3 itself works out whether a bucket's policy makes it public - the same
judgement the console's "Public" badge is built on - so the check asks it
rather than parsing policies. Separately, a bucket with Block Public Access
switched off has nothing stopping the next policy edit from publishing it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check

MODULE = "security"

#: The four switches Block Public Access is made of.
BLOCK_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

#: GetBucketLocation answers with these for the two regions that predate it.
LEGACY_LOCATIONS = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}


def public_buckets(ctx: ScanContext) -> Iterator[Finding]:
    """Buckets whose policy makes them public, and buckets nothing stops going public."""
    scanned = set(ctx.regions)
    for bucket in ctx.collect("s3:ListAllMyBuckets", "Buckets"):
        name = str(bucket.get("Name"))
        region = _region_of(ctx, name)
        if region not in scanned:
            continue
        ctx.looked_at()

        arn = f"arn:{ctx.identity.partition}:s3:::{name}"
        tags = dict(ctx.tags_for(region, arn))
        if ignored(tags):
            continue

        public = _policy_is_public(ctx, name, region)
        block = _public_access_block(ctx, name, region)
        off = [setting for setting in BLOCK_SETTINGS if not block.get(setting)]
        resource = Resource(id=name, kind="s3:bucket", region=region, arn=arn, tags=tags)

        if public:
            evidence = [
                "S3 reports the bucket policy as public: it grants access to "
                "anyone, without signing in.",
            ]
            if not block:
                evidence.append("Block Public Access isn't configured on the bucket.")
            elif off:
                evidence.append("Block Public Access is partly off: " + ", ".join(off) + ".")
            yield Finding(
                check="public-buckets",
                module=MODULE,
                title="Bucket with a public policy",
                resource=resource,
                evidence=tuple(evidence),
                recommendation=(
                    "If it shouldn't be public, remove the statement granting "
                    "Principal '*' and switch Block Public Access on. If it's a "
                    "website or a public dataset, put CloudFront in front of it - "
                    "or tag it 'preflight:ignore' so this stops coming up."
                ),
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
            )
        elif not block:
            yield Finding(
                check="public-buckets",
                module=MODULE,
                title="Nothing stops this bucket being made public",
                resource=resource,
                evidence=(
                    "Block Public Access isn't configured on the bucket, so one "
                    "policy or ACL edit would make it public.",
                    "The account-wide setting may still cover it; reading that "
                    "needs a permission this check doesn't ask for.",
                ),
                recommendation=(
                    "Switch Block Public Access on for the bucket - or for the whole "
                    "account, if nothing in it is meant to be public."
                ),
                confidence=Confidence.MEDIUM,
                severity=Severity.LOW,
            )


def _region_of(ctx: ScanContext, bucket: str) -> str:
    answer = ctx.call("s3:GetBucketLocation", Bucket=bucket)
    location = answer.get("LocationConstraint")
    return LEGACY_LOCATIONS.get(location, str(location))


def _policy_is_public(ctx: ScanContext, bucket: str, region: str) -> bool:
    """S3's own verdict on the bucket policy. No policy at all is not public."""
    from preflight.core import aws

    try:
        status = ctx.call("s3:GetBucketPolicyStatus", region=region, Bucket=bucket)
    except aws.NotFound:
        return False
    return bool((status.get("PolicyStatus") or {}).get("IsPublic"))


def _public_access_block(ctx: ScanContext, bucket: str, region: str) -> dict[str, Any]:
    """The bucket's Block Public Access settings; empty if it has none."""
    from preflight.core import aws

    try:
        answer = ctx.call("s3:GetBucketPublicAccessBlock", region=region, Bucket=bucket)
    except aws.NotFound:
        return {}
    return dict(answer.get("PublicAccessBlockConfiguration") or {})


PUBLIC_BUCKETS = Check(
    key="public-buckets",
    title="Public buckets",
    looks_for="S3 buckets a policy makes public, or that nothing stops going public.",
    actions=(
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
    ),
    run=public_buckets,
)
