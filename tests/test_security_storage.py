"""Buckets anyone can read."""

from __future__ import annotations

from botocore.exceptions import ClientError
from conftest import denied, findings, run

from preflight.core.findings import Confidence, Severity
from preflight.modules.security.storage import PUBLIC_BUCKETS

BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def no_such(code):
    return ClientError({"Error": {"Code": code, "Message": "none"}}, "Get")


def bucket(public=False, block=BLOCKED, location=None, name="assets", **more):
    return {
        "list_buckets": {"Buckets": [{"Name": name}]},
        "get_bucket_location": {"LocationConstraint": location},
        "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": public}},
        "get_bucket_public_access_block": (
            {"PublicAccessBlockConfiguration": block}
            if block is not None
            else no_such("NoSuchPublicAccessBlockConfiguration")
        ),
        **more,
    }


def test_a_private_blocked_bucket_is_fine():
    outcome = run(PUBLIC_BUCKETS, bucket())
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_bucket_with_a_public_policy():
    found = findings(PUBLIC_BUCKETS, bucket(public=True, block=None))
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Bucket with a public policy"
    assert finding.resource.id == "assets"
    assert finding.resource.arn == "arn:aws:s3:::assets"
    assert finding.resource.region == "us-east-1"
    assert finding.level is Severity.HIGH
    assert any("isn't configured" in line for line in finding.evidence)


def test_says_which_block_settings_are_off():
    partial = {**BLOCKED, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    found = findings(PUBLIC_BUCKETS, bucket(public=True, block=partial))
    assert any("BlockPublicPolicy, RestrictPublicBuckets" in line for line in found[0].evidence)


def test_a_bucket_with_no_policy_is_not_public():
    """`NoSuchBucketPolicy` is S3 saying there's nothing to be public."""
    responses = bucket(get_bucket_policy_status=no_such("NoSuchBucketPolicy"))
    assert findings(PUBLIC_BUCKETS, responses) == ()


def test_no_block_at_all_is_a_gentle_finding():
    found = findings(PUBLIC_BUCKETS, bucket(block=None))
    assert found[0].title == "Nothing stops this bucket being made public"
    assert found[0].level is Severity.LOW
    assert found[0].confidence is Confidence.MEDIUM


def test_buckets_outside_the_scanned_regions_are_left_out():
    outcome = run(PUBLIC_BUCKETS, bucket(public=True, location="ap-south-1"))
    assert outcome.findings == ()
    assert outcome.examined == 0


def test_the_legacy_eu_location_means_ireland():
    found = findings(PUBLIC_BUCKETS, bucket(public=True, location="EU"), regions=("eu-west-1",))
    assert found[0].resource.region == "eu-west-1"


def test_respects_the_ignore_tag_from_the_tagging_api():
    tagged = {
        "get_resources": {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:s3:::assets",
                    "Tags": [{"Key": "preflight:ignore", "Value": "website"}],
                }
            ]
        }
    }
    assert findings(PUBLIC_BUCKETS, bucket(public=True, **tagged)) == ()


def test_missing_policy_status_permission_skips_and_names_it():
    responses = bucket(get_bucket_policy_status=denied("GetBucketPolicyStatus", "AccessDenied"))
    outcome = run(PUBLIC_BUCKETS, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "s3:GetBucketPolicyStatus"
