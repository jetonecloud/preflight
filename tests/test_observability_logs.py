"""Log groups kept forever."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run

from preflight.core.findings import Confidence, Severity
from preflight.modules.observability.logs import (
    BYTES_PER_GB,
    LARGE_STORED_GB,
    LOG_GROUPS_KEPT_FOREVER,
    MIN_GROUP_AGE_DAYS,
    MIN_STORED_GB,
)

ARN = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/checkout"


def group(name="/aws/lambda/checkout", gb=20.0, age=200, retention=None, **extra):
    data = {
        "logGroupName": name,
        "creationTime": int(days_ago(age).timestamp() * 1000),
        "storedBytes": int(gb * BYTES_PER_GB),
        "arn": f"{ARN}:*",
        "logGroupArn": ARN,
        **extra,
    }
    if retention is not None:
        data["retentionInDays"] = retention
    return data


def groups(*items, **more):
    return {"describe_log_groups": {"logGroups": list(items)}, **more}


def test_flags_a_large_group_with_no_retention():
    found = findings(LOG_GROUPS_KEPT_FOREVER, groups(group(gb=20)))
    assert len(found) == 1
    finding = found[0]
    assert finding.resource.id == "/aws/lambda/checkout"
    assert finding.resource.arn == ARN
    assert finding.confidence is Confidence.HIGH
    assert finding.level is Severity.LOW
    # No saving is claimed: retention's effect depends on data we can't see.
    assert finding.estimate is None
    assert any("$0.60/month" in line for line in finding.evidence)


def test_a_very_large_group_is_medium_severity():
    found = findings(LOG_GROUPS_KEPT_FOREVER, groups(group(gb=LARGE_STORED_GB + 1)))
    assert found[0].level is Severity.MEDIUM


def test_a_group_with_retention_is_left_alone():
    assert findings(LOG_GROUPS_KEPT_FOREVER, groups(group(retention=30))) == ()


def test_a_small_group_is_not_worth_mentioning():
    tiny = group(gb=MIN_STORED_GB / 2)
    outcome = run(LOG_GROUPS_KEPT_FOREVER, groups(tiny))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_a_brand_new_group_gets_a_week():
    young = group(age=MIN_GROUP_AGE_DAYS - 1)
    assert findings(LOG_GROUPS_KEPT_FOREVER, groups(young)) == ()


def test_creation_time_is_read_as_milliseconds():
    found = findings(LOG_GROUPS_KEPT_FOREVER, groups(group(age=200)))
    assert any("Created 200 days ago" in line for line in found[0].evidence)


def test_respects_the_ignore_tag_from_the_tagging_api():
    tagged = {
        "get_resources": {
            "ResourceTagMappingList": [
                {"ResourceARN": ARN, "Tags": [{"Key": "preflight:ignore", "Value": "audit"}]}
            ]
        }
    }
    assert findings(LOG_GROUPS_KEPT_FOREVER, groups(group(), **tagged)) == ()


def test_builds_an_arn_when_the_api_leaves_it_out():
    bare = group()
    del bare["arn"], bare["logGroupArn"]
    found = findings(LOG_GROUPS_KEPT_FOREVER, groups(bare))
    assert found[0].resource.arn == ARN


def test_missing_permission_skips_the_check_and_names_the_action():
    outcome = run(LOG_GROUPS_KEPT_FOREVER, {"describe_log_groups": denied("DescribeLogGroups")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "logs:DescribeLogGroups"
