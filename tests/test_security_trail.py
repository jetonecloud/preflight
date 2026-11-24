"""Whether anything records what happens in the account."""

from __future__ import annotations

from conftest import denied, findings, run, tags

from preflight.core.findings import Severity
from preflight.modules.security.trail import TRAIL_COVERAGE

ACCOUNT = "123456789012"
BOTH = ("us-east-1", "eu-west-1")


def trail(name="org-audit", home="us-east-1", multi=True):
    return {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:{home}:{ACCOUNT}:trail/{name}",
        "HomeRegion": home,
        "IsMultiRegionTrail": multi,
    }


def account(*trails, logging=True, **more):
    def status(Name):
        if isinstance(logging, dict):
            return {"IsLogging": logging.get(Name.rsplit("/", 1)[-1], True)}
        return {"IsLogging": logging}

    return {
        "describe_trails": {"trailList": list(trails)},
        "get_trail_status": status,
        **more,
    }


def test_a_logging_multi_region_trail_covers_everything():
    outcome = run(TRAIL_COVERAGE, account(trail()), regions=BOTH)
    assert outcome.findings == ()
    assert outcome.examined == 2


def test_no_trail_anywhere_is_one_finding_about_the_account():
    found = findings(TRAIL_COVERAGE, account(), regions=BOTH)
    assert len(found) == 1
    assert found[0].title == "No CloudTrail trail at all"
    assert found[0].resource.region == "global"
    assert found[0].level is Severity.HIGH


def test_a_trail_that_stopped_logging_is_named():
    found = findings(TRAIL_COVERAGE, account(trail(), logging=False), regions=BOTH)
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Trail that has stopped logging"
    assert finding.resource.id == "org-audit"
    assert "us-east-1, eu-west-1" in finding.evidence[0]
    assert finding.level is Severity.HIGH


def test_a_single_region_trail_leaves_the_other_regions_uncovered():
    found = findings(TRAIL_COVERAGE, account(trail(multi=False)), regions=BOTH)
    assert len(found) == 1
    assert found[0].title == "Region no trail is recording"
    assert found[0].resource.region == "eu-west-1"
    assert found[0].level is Severity.MEDIUM


def test_one_logging_trail_is_enough_even_if_another_stopped():
    responses = account(trail("old", multi=True), trail("new", multi=True), logging={"old": False})
    assert findings(TRAIL_COVERAGE, responses, regions=BOTH) == ()


def test_respects_the_ignore_tag_on_a_stopped_trail():
    arn = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-audit"
    tagged = {
        "get_resources": {
            "ResourceTagMappingList": [
                {"ResourceARN": arn, "Tags": tags(**{"preflight:ignore": "replaced"})}
            ]
        }
    }
    assert findings(TRAIL_COVERAGE, account(trail(), logging=False, **tagged)) == ()


def test_missing_permission_skips_and_names_it():
    outcome = run(TRAIL_COVERAGE, {"describe_trails": denied("DescribeTrails")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "cloudtrail:DescribeTrails"
