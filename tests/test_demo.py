"""The sample account.

`preflight demo` is the first thing most people run, and it runs the real
checks — so these tests are really testing the whole pipeline end to end:
nine checks, two regions, metrics, pricing, grouping and both output
formats. They also pin the near-misses, because the sample is only
convincing if the guards visibly hold.
"""

from __future__ import annotations

import json

from preflight import demo
from preflight.core.report import write


def report():
    return demo.build()


def test_every_check_runs_and_nothing_is_skipped():
    result = report()
    assert len(result.outcomes) == 9
    assert all(outcome.ran for outcome in result.outcomes)
    assert result.complete


def test_the_sample_is_worth_reading():
    result = report()
    assert result.findings
    assert result.monthly_usd > 0
    assert result.by_severity["high"] >= 1, "a sample with nothing serious isn't a sample"
    assert len(result.headline) == 3
    assert result.spend is not None
    assert 0 < result.share_of_spend < 1


def test_it_is_marked_as_sample_data_everywhere():
    result = report()
    assert result.demo
    assert "Sample data" in result.to_html()
    assert json.loads(result.to_json())["scan"]["demo"] is True


def test_it_covers_more_than_one_region():
    regions = {finding.resource.region for finding in report().findings}
    assert len(regions) > 1


def found_ids(result) -> set[str]:
    return {finding.resource.id for finding in result.findings}


def test_the_guards_hold_on_the_sample_account():
    """Each of these is in the data precisely so a check can decline it."""
    ids = found_ids(report())

    assert "vol-0a1b2c3d4e5f60003" not in ids, "detached three days ago"
    assert "vol-0f9e8d7c6b5a40002" not in ids, "tagged preflight:ignore"
    assert "eipalloc-0123456789abcdef2" not in ids, "attached to an instance"
    assert "nat-0123456789abcdef1" not in ids, "moving real traffic"
    assert "prod-alb" not in ids, "healthy targets and requests"
    assert "i-0dd1ce4455667702" not in ids, "stopped less than a month ago"
    assert "i-0b5a9c1d2e3f40002" not in ids, "busy, and in an autoscaling group"
    assert "snap-0123456789abcdef1" not in ids, "an AMI depends on it"
    assert "snap-0123456789abcdef2" not in ids, "three weeks old"
    assert "app-prod" not in ids, "a running database"
    assert "app-prod-recent" not in ids, "a recent manual snapshot"


def test_the_findings_that_should_be_there_are():
    ids = found_ids(report())
    assert "vol-0a1b2c3d4e5f60001" in ids, "500 GB detached for seven months"
    assert "nat-0123456789abcdef0" in ids, "no bytes in a fortnight"
    assert "legacy-site-elb" in ids, "a classic balancer with no instances"
    assert "analytics-staging" in ids, "a stopped database still billing storage"
    assert "i-0b5a9c1d2e3f40001" in ids, "an instance at 3% CPU"


def test_every_finding_shows_its_arithmetic():
    for finding in report().findings:
        assert finding.estimate is not None, finding.title
        assert finding.estimate.basis.endswith("."), finding.title
        assert finding.monthly_usd > 0
        assert finding.evidence
        assert finding.recommendation


def test_the_dates_move_with_the_calendar():
    """A sample that says "stopped in 2025" ages badly."""
    stopped = next(f for f in report().findings if f.check == "long-stopped-instances")
    assert "118 days" in stopped.title


def test_it_writes_both_formats(tmp_path):
    paths = write(report(), tmp_path)
    assert paths["html"].exists() and paths["json"].exists()
    assert paths["html"].read_text(encoding="utf-8").startswith("<!doctype html>")
    json.loads(paths["json"].read_text(encoding="utf-8"))


def test_it_can_be_redacted_like_any_other_report():
    hidden = report().redact()
    assert "123456789012" not in json.dumps(hidden.to_dict())
    assert hidden.monthly_usd == report().monthly_usd


def test_two_runs_agree():
    """Nothing in the sample depends on dict ordering or the clock drifting."""
    first, second = report(), report()
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert first.monthly_usd == second.monthly_usd
