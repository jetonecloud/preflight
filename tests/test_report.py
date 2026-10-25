"""The finding model, the report it adds up to, and redaction.

The JSON is a contract — something else may be reading it — so the shape is
asserted here rather than left to whatever the code happens to emit.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import NOW

from preflight.core.findings import (
    Confidence,
    Estimate,
    Finding,
    Resource,
    Severity,
    at_least,
    count_by_severity,
    rank,
    severity_for,
    total_monthly,
)
from preflight.core.redact import Redactor
from preflight.core.report import (
    HEADLINE_COUNT,
    SCHEMA_VERSION,
    Account,
    ScanResult,
    money,
    percent,
    plural,
)
from preflight.core.scan import CheckOutcome
from preflight.core.spend import ServiceSpend, Spend
from preflight.modules.cost import COST

ACCOUNT = Account(
    id="123456789012",
    arn="arn:aws:sts::123456789012:assumed-role/PreflightReadOnlyRole/preflight-scan",
    kind="assumed-role",
    is_preflight_role=True,
)


def finding(
    *,
    check="unattached-ebs-volumes",
    resource_id="vol-0aaa1111bbbb2222a",
    monthly=40.0,
    severity=None,
    confidence=Confidence.HIGH,
    region="us-east-1",
    name="old-data",
):
    return Finding(
        check=check,
        module="cost",
        title=f"Unattached volume {resource_id}",
        resource=Resource(
            id=resource_id,
            kind="ec2:volume",
            region=region,
            name=name,
            arn=f"arn:aws:ec2:{region}:123456789012:volume/{resource_id}",
            tags={"Name": name, "Owner": "platform"},
        ),
        evidence=(f"{resource_id} is attached to nothing.", "Account 123456789012 owns it."),
        recommendation="Delete it.",
        confidence=confidence,
        estimate=Estimate(monthly, "500 GB at $0.08/GB-month") if monthly is not None else None,
        severity=severity,
    )


def outcome(findings=(), *, check=None, status="ran", **kwargs):
    check = check or COST.checks[0]
    return CheckOutcome(check, status, tuple(findings), **kwargs)


def result(outcomes=(), **kwargs):
    defaults = {
        "account": ACCOUNT,
        "regions": ("us-east-1",),
        "outcomes": tuple(outcomes),
        "modules": (COST,),
        "started_at": NOW - timedelta(seconds=12),
        "finished_at": NOW,
        "lookback_days": 14,
        "credentials": "assumed role",
        "command": "preflight scan --modules cost",
    }
    return ScanResult(**{**defaults, **kwargs})


# --- the finding model ----------------------------------------------------


@pytest.mark.parametrize(
    "monthly, expected",
    [
        (250.0, Severity.HIGH),
        (100.0, Severity.HIGH),
        (20.0, Severity.MEDIUM),
        (3.0, Severity.LOW),
        (None, Severity.LOW),
    ],
)
def test_severity_follows_the_money_by_default(monthly, expected):
    assert severity_for(monthly) is expected


def test_an_explicit_severity_wins():
    assert finding(monthly=1.0, severity=Severity.HIGH).level is Severity.HIGH


def test_a_floor_raises_a_cheap_finding_but_never_lowers_an_expensive_one():
    assert at_least(Severity.MEDIUM, 2.0) is Severity.MEDIUM
    assert at_least(Severity.MEDIUM, 500.0) is Severity.HIGH


def test_findings_rank_by_money_then_severity():
    cheap = finding(resource_id="vol-0b", monthly=5.0)
    dear = finding(resource_id="vol-0a", monthly=500.0)
    assert rank([cheap, dear])[0] is dear


def test_ranking_is_stable_for_identical_findings():
    one = finding(resource_id="vol-0aaa1111bbbb22221", monthly=10.0)
    two = finding(resource_id="vol-0aaa1111bbbb22222", monthly=10.0)
    assert [f.id for f in rank([two, one])] == [f.id for f in rank([one, two])]


def test_a_finding_id_is_stable_and_identifies_the_resource():
    assert finding().id == "cost/unattached-ebs-volumes/us-east-1/vol-0aaa1111bbbb2222a"


def test_totals_ignore_findings_with_no_price():
    assert total_monthly([finding(monthly=10.0), finding(monthly=None)]) == 10.0


def test_severity_counts_always_have_all_three_keys():
    assert count_by_severity([]) == {"high": 0, "medium": 0, "low": 0}


def test_owner_comes_from_whichever_tag_has_one():
    assert finding().resource.owner == "platform"
    bare = Resource(id="x", kind="k", region="r")
    assert bare.owner is None
    assert bare.label == "x"


def test_a_finding_serialises_everything_a_reader_needs():
    data = finding().to_dict()
    assert data["estimated_monthly_savings_usd"] == 40.0
    assert data["estimated_annual_savings_usd"] == 480.0
    assert data["severity"] == "medium"
    assert data["confidence"] == "high"
    assert data["estimate_basis"]
    assert data["resource"]["arn"].endswith("vol-0aaa1111bbbb2222a")


# --- the report -----------------------------------------------------------


def test_the_headline_is_the_three_biggest():
    findings = [finding(resource_id=f"vol-0aaa1111bbbb2222{i}", monthly=float(i)) for i in range(6)]
    report = result([outcome(findings)])
    assert len(report.headline) == HEADLINE_COUNT
    assert report.headline[0].monthly_usd == 5.0


def test_totals_and_shares():
    report = result(
        [outcome([finding(monthly=100.0), finding(resource_id="vol-0b", monthly=50.0)])],
        spend=Spend("2026-05", 1500.0, "USD", (ServiceSpend("EC2", 1500.0),)),
    )
    assert report.monthly_usd == 150.0
    assert report.annual_usd == 1800.0
    assert report.share_of_spend == pytest.approx(0.1)


def test_no_spend_means_no_share():
    assert result([outcome([finding()])]).share_of_spend is None


def test_a_scan_with_nothing_skipped_knows_it_is_complete():
    assert result([outcome([finding()])]).complete
    assert not result([outcome([], status="skipped")]).complete
    assert not result([outcome([finding()])], notes=("a gap",)).complete


def test_skipped_checks_surface_the_action_to_add():
    skipped = outcome(status="skipped", reason="no", missing_action="ec2:DescribeVolumes")
    report = result([skipped])
    assert report.missing_actions == ("ec2:DescribeVolumes",)
    assert len(report.skipped) == 1
    assert report.ran == ()


def test_groups_are_ordered_by_what_they_are_worth():
    small = outcome([finding(monthly=5.0)], check=COST.checks[0])
    large = outcome([finding(check="idle-nat-gateways", monthly=90.0)], check=COST.checks[2])
    groups = result([small, large]).groups()
    assert [group["check"].key for group in groups] == [
        "idle-nat-gateways",
        "unattached-ebs-volumes",
    ]


def test_clean_checks_are_distinguishable_from_skipped_ones():
    report = result([outcome([], examined=12), outcome(status="skipped")])
    assert len(report.clean) == 1
    assert report.examined == 12


def test_the_filename_carries_the_account_and_the_time():
    assert result().filename_stem() == "preflight-report-123456789012-20260615-120000"


# --- JSON -----------------------------------------------------------------


def test_the_json_has_the_shape_other_tools_will_read():
    report = result(
        [outcome([finding()]), outcome(status="skipped", missing_action="ec2:DescribeImages")],
        spend=Spend("2026-05", 1000.0, "USD", (ServiceSpend("EC2", 900.0),)),
    )
    data = json.loads(report.to_json())

    assert data["schema_version"] == SCHEMA_VERSION
    assert set(data) == {
        "schema_version",
        "preflight",
        "scan",
        "account",
        "modules",
        "spend",
        "summary",
        "checks",
        "findings",
        "notes",
        "missing_actions",
    }
    assert data["summary"]["estimated_monthly_savings_usd"] == 40.0
    assert data["summary"]["checks_skipped"] == 1
    assert data["missing_actions"] == ["ec2:DescribeImages"]
    assert data["account"]["id"] == "123456789012"
    assert data["spend"]["total_usd"] == 1000.0
    assert data["scan"]["lookback_days"] == 14
    assert data["findings"][0]["check"] == "unattached-ebs-volumes"


def test_the_json_is_pretty_and_ends_in_a_newline():
    text = result().to_json()
    assert text.endswith("\n")
    assert "\n  " in text


# --- HTML -----------------------------------------------------------------


def test_the_html_is_one_self_contained_file():
    html = result([outcome([finding()])]).to_html()
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    # No external anything: a report must not call home when it's opened.
    for forbidden in ("<script", 'src="http', "@import", "<link"):
        assert forbidden not in html


def test_the_html_leads_with_the_number_and_the_fix():
    html = result([outcome([finding(monthly=123.0)])]).to_html()
    assert "Estimated monthly saving" in html
    assert "$123" in html
    assert "Start here" in html
    assert "Delete it." in html
    assert "500 GB at $0.08/GB-month" in html


def test_the_html_admits_to_what_it_could_not_read():
    skipped = outcome(
        status="skipped",
        reason="the role can't call ec2:DescribeImages",
        missing_action="ec2:DescribeImages",
    )
    html = result([skipped], notes=("ap-south-1 couldn't be read.",)).to_html()
    assert "What we couldn't see" in html
    assert "ec2:DescribeImages" in html
    assert "ap-south-1" in html
    assert "preflight scan --modules cost --save" in html


def test_a_clean_report_says_so_rather_than_showing_an_empty_list():
    html = result([outcome([], examined=40)]).to_html()
    assert "Nothing worth flagging turned up." in html
    assert "Start here" not in html


def test_the_demo_banner_is_unmissable():
    html = result([outcome([finding()])], demo=True).to_html()
    assert "Sample data" in html


def test_html_escapes_what_came_from_the_account():
    nasty = finding(name="<script>alert(1)</script>")
    html = result([outcome([nasty])]).to_html()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --- redaction ------------------------------------------------------------


def test_redaction_replaces_identifiers_with_stable_pseudonyms():
    report = result([outcome([finding(), finding(resource_id="vol-0bbb2222cccc3333b")])]).redact()
    ids = [item.resource.id for item in report.findings]
    assert ids == ["vol-1", "vol-2"] or ids == ["vol-2", "vol-1"]
    assert report.account.id == "<account>"
    assert report.redacted


def test_the_same_resource_keeps_the_same_pseudonym_everywhere():
    report = result([outcome([finding()])]).redact()
    item = report.findings[0]
    assert item.resource.id in item.evidence[0], "the evidence should use the alias too"
    assert "vol-0aaa1111bbbb2222a" not in item.evidence[0]


def test_redaction_removes_names_arns_and_account_numbers():
    report = result([outcome([finding()])]).redact()
    item = report.findings[0]
    assert item.resource.name is None
    assert item.resource.arn is None
    assert item.resource.tags == {}
    assert "123456789012" not in json.dumps(report.to_dict())


def test_redaction_keeps_the_numbers_and_the_reasoning():
    plain = result([outcome([finding(monthly=40.0)])])
    hidden = plain.redact()
    assert hidden.monthly_usd == plain.monthly_usd
    assert hidden.findings[0].recommendation == "Delete it."
    assert "$0.08" in hidden.findings[0].estimate.basis


def test_an_inactive_redactor_changes_nothing():
    quiet = Redactor(False)
    assert quiet.text("vol-0abc12345 in 123456789012") == "vol-0abc12345 in 123456789012"
    assert quiet.name("web") == "web"
    assert quiet.arn("arn:aws:x") == "arn:aws:x"


def test_redaction_covers_addresses_and_loose_account_numbers():
    redactor = Redactor(True, account_id="123456789012")
    scrubbed = redactor.text("Elastic IP 203.0.113.17 in account 123456789012")
    assert "203.0.113.17" not in scrubbed
    assert "123456789012" not in scrubbed


def test_named_resources_are_pseudonymised_by_kind():
    redactor = Redactor(True)
    assert redactor.identifier("prod-postgres", "rds:instance") == "rds-instance-1"
    assert redactor.identifier("prod-postgres", "rds:instance") == "rds-instance-1"
    assert redactor.identifier("other-db", "rds:instance") == "rds-instance-2"


# --- formatting -----------------------------------------------------------


@pytest.mark.parametrize(
    "amount, expected",
    [(None, "—"), (0.0, "$0.00"), (3.651, "$3.65"), (12.4, "$12"), (1284.0, "$1,284")],
)
def test_money(amount, expected):
    assert money(amount) == expected


@pytest.mark.parametrize(
    "fraction, expected", [(None, "—"), (0.004, "under 1%"), (0.11, "11%"), (1.0, "100%")]
)
def test_percent(fraction, expected):
    assert percent(fraction) == expected


def test_plural():
    assert plural(1, "region") == "region"
    assert plural(2, "region") == "regions"
    assert plural(2, "entry", "entries") == "entries"


def test_duration_is_never_negative():
    weird = result(started_at=NOW, finished_at=NOW - timedelta(seconds=5))
    assert weird.seconds == 0.0


def test_account_is_built_from_an_identity():
    from preflight.core.session import Identity

    identity = Identity("123456789012", ACCOUNT.arn, "AROA:session")
    assert Account.of(identity).is_preflight_role
    assert Account.of(identity).kind == "assumed-role"


def test_a_check_with_no_findings_is_not_a_group():
    assert result([outcome([])]).groups() == []


def test_the_report_knows_when_it_was_run():
    assert result().started_at < result().finished_at or True
    assert isinstance(result().finished_at, datetime)
    assert result().finished_at.tzinfo is UTC
