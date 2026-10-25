"""The scan runner: permissions, caching, and admitting to gaps.

The property this file exists to protect is the one in `CONTRIBUTING.md`:
a check can only make the calls it declared. Everything else here is about
the runner turning failures into something the report can say out loud.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError
from conftest import NOW, denied, make_context

from preflight.core import aws
from preflight.core.findings import Confidence, Estimate, Finding, Resource
from preflight.core.metrics import MetricRequest
from preflight.core.scan import (
    ScanContext,
    UndeclaredAction,
    ignored,
    name_of,
    parse_timestamp,
    run_check,
    run_module,
    tags_to_dict,
)
from preflight.modules.base import Check, Module, ModuleStatus


def a_finding(check="demo"):
    return Finding(
        check=check,
        module="test",
        title="Something",
        resource=Resource(id="r-1", kind="test:thing", region="us-east-1"),
        evidence=("because",),
        recommendation="do the thing",
        estimate=Estimate(10.0, "ten dollars"),
        confidence=Confidence.HIGH,
    )


def check_that(run, *, actions=("ec2:DescribeVolumes",), key="demo"):
    return Check(key=key, title="Demo", looks_for="demo things", actions=actions, run=run)


# --- the permission contract ----------------------------------------------


def test_a_check_cannot_call_something_it_did_not_declare():
    def overreach(ctx):
        ctx.collect("ec2:DescribeInstances", "Reservations")
        return ()

    ctx = make_context({"describe_instances": {"Reservations": []}})
    with pytest.raises(UndeclaredAction) as caught:
        run_check(ctx, check_that(overreach, actions=("ec2:DescribeVolumes",)))
    assert "ec2:DescribeInstances" in str(caught.value)


def test_the_declared_call_goes_through():
    def declared(ctx):
        assert ctx.collect("ec2:DescribeVolumes", "Volumes") == [{"VolumeId": "vol-1"}]
        return ()

    ctx = make_context({"describe_volumes": {"Volumes": [{"VolumeId": "vol-1"}]}})
    assert run_check(ctx, check_that(declared)).status == "ran"


def test_the_permission_window_closes_when_the_check_ends():
    """One check's permissions don't leak into the next one's."""
    ctx = make_context({"describe_volumes": {"Volumes": []}})
    run_check(ctx, check_that(lambda c: ()))
    with pytest.raises(UndeclaredAction):
        ctx.collect("ec2:DescribeVolumes", "Volumes")


def test_pricing_lookups_go_through_the_same_gate():
    def price(ctx):
        ctx.prices.hourly("us-east-1", "m5.large")
        return ()

    ctx = make_context({"get_products": {"PriceList": []}})
    with pytest.raises(UndeclaredAction):
        run_check(ctx, check_that(price, actions=("ec2:DescribeVolumes",)))


# --- outcomes -------------------------------------------------------------


def test_a_denied_call_skips_the_check_and_keeps_the_action():
    def read(ctx):
        ctx.collect("ec2:DescribeVolumes", "Volumes")
        return ()

    outcome = run_check(
        make_context({"describe_volumes": denied("DescribeVolumes")}), check_that(read)
    )
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ec2:DescribeVolumes"
    assert "ec2:DescribeVolumes" in outcome.reason


def test_an_unexpected_aws_error_fails_the_check_without_stopping_the_scan():
    throttled = ClientError(
        {"Error": {"Code": "Throttling", "Message": "rate exceeded"}}, "DescribeVolumes"
    )

    def read(ctx):
        ctx.collect("ec2:DescribeVolumes", "Volumes")
        return ()

    outcome = run_check(make_context({"describe_volumes": throttled}), check_that(read))
    assert outcome.status == "failed"
    assert "rate exceeded" in outcome.reason


def test_expired_credentials_end_the_scan_rather_than_one_check():
    expired = ClientError(
        {"Error": {"Code": "ExpiredToken", "Message": "token expired"}}, "DescribeVolumes"
    )

    def read(ctx):
        ctx.collect("ec2:DescribeVolumes", "Volumes")
        return ()

    with pytest.raises(aws.CredentialsError):
        run_check(make_context({"describe_volumes": expired}), check_that(read))


def test_outcomes_carry_what_was_looked_at():
    def read(ctx):
        ctx.looked_at(7)
        return [a_finding()]

    outcome = run_check(make_context(), check_that(read))
    assert outcome.examined == 7
    assert len(outcome.findings) == 1
    assert not outcome.clean


def test_a_module_runs_its_checks_in_order_and_only_selects_what_was_asked():
    ran: list[str] = []

    def record(key):
        def run(ctx):
            ran.append(key)
            return ()

        return run

    module = Module(
        key="test",
        name="Test",
        summary="",
        iam_actions=("ec2:DescribeVolumes",),
        status=ModuleStatus.AVAILABLE,
        checks=(
            check_that(record("one"), key="one"),
            check_that(record("two"), key="two"),
        ),
    )
    run_module(make_context(), module)
    assert ran == ["one", "two"]

    ran.clear()
    outcomes = run_module(make_context(), module, only=["two"])
    assert ran == ["two"]
    assert len(outcomes) == 1


# --- degrading gracefully -------------------------------------------------


def test_a_region_that_will_not_answer_is_noted_and_skipped():
    unavailable = ClientError(
        {"Error": {"Code": "OptInRequired", "Message": "not enabled"}}, "DescribeVolumes"
    )

    def read(ctx):
        return (
            [a_finding()]
            if ctx.collect("ec2:DescribeVolumes", "Volumes", region="ap-south-1")
            else []
        )

    ctx = make_context({"describe_volumes": unavailable}, regions=("ap-south-1",))
    outcome = run_check(ctx, check_that(read))
    assert outcome.status == "ran"
    assert outcome.findings == ()
    assert any("ap-south-1" in note for note in ctx.notes)


def test_a_region_is_only_noted_once():
    unavailable = ClientError(
        {"Error": {"Code": "OptInRequired", "Message": "not enabled"}}, "DescribeVolumes"
    )

    def read(ctx):
        for _ in range(3):
            ctx.collect("ec2:DescribeVolumes", "Volumes", region="ap-south-1", cache=False)
        return ()

    ctx = make_context({"describe_volumes": unavailable}, regions=("ap-south-1",))
    run_check(ctx, check_that(read))
    assert len(ctx.notes) == 1


def test_denied_tags_degrade_the_report_rather_than_the_check():
    def read(ctx):
        assert ctx.tags_for("us-east-1", "arn:aws:x") == {}
        return [a_finding()]

    ctx = make_context({"get_resources": denied("GetResources")})
    outcome = run_check(ctx, check_that(read))
    assert outcome.status == "ran"
    assert any("owner names" in note for note in ctx.notes)


def test_tags_are_looked_up_by_arn():
    responses = {
        "get_resources": {
            "ResourceTagMappingList": [
                {"ResourceARN": "arn:aws:x", "Tags": [{"Key": "Owner", "Value": "platform"}]}
            ]
        }
    }

    def read(ctx):
        assert ctx.tags_for("us-east-1", "arn:aws:x") == {"Owner": "platform"}
        assert ctx.tags_for("us-east-1", "arn:aws:missing") == {}
        return ()

    assert run_check(make_context(responses), check_that(read)).status == "ran"


# --- the read cache -------------------------------------------------------


def test_identical_reads_are_only_made_once():
    def read(ctx):
        ctx.collect("ec2:DescribeVolumes", "Volumes")
        ctx.collect("ec2:DescribeVolumes", "Volumes")
        return ()

    ctx = make_context({"describe_volumes": {"Volumes": []}})
    run_check(ctx, check_that(read))
    client = ctx.session.clients[("ec2", "us-east-1")]
    assert len(client.calls) == 1


def test_different_parameters_are_different_reads():
    def read(ctx):
        ctx.collect("ec2:DescribeVolumes", "Volumes", Filters=[{"Name": "status"}])
        ctx.collect("ec2:DescribeVolumes", "Volumes")
        return ()

    ctx = make_context({"describe_volumes": {"Volumes": []}})
    run_check(ctx, check_that(read))
    assert len(ctx.session.clients[("ec2", "us-east-1")].calls) == 2


# --- small helpers --------------------------------------------------------


def test_tags_become_a_dict():
    assert tags_to_dict([{"Key": "Name", "Value": "web"}]) == {"Name": "web"}
    assert tags_to_dict(None) == {}
    assert tags_to_dict([{"Value": "orphan"}]) == {}


def test_name_comes_from_either_spelling():
    assert name_of({"Name": "web"}) == "web"
    assert name_of({"name": "web"}) == "web"
    assert name_of({}) is None


@pytest.mark.parametrize(
    "tags, expected",
    [
        ({}, False),
        ({"preflight:ignore": ""}, True),
        ({"preflight:ignore": "because"}, True),
        ({"preflight-ignore": "true"}, True),
        ({"PreflightIgnore": "1"}, True),
        ({"preflight:ignore": "false"}, False),
        ({"preflight:ignore": "NO"}, False),
        ({"preflight:ignore": "off"}, False),
    ],
)
def test_the_ignore_tag_reads_sensibly(tags, expected):
    assert ignored(tags) is expected


def test_timestamps_come_back_aware_whatever_went_in():
    assert parse_timestamp(None) is None
    assert parse_timestamp("nonsense") is None
    assert parse_timestamp("2026-01-02T03:04:05Z").tzinfo is not None
    naive = datetime(2026, 1, 2)
    assert parse_timestamp(naive).tzinfo is UTC


def test_days_since_measures_from_the_scan_clock():
    ctx = make_context(now=NOW)
    assert round(ctx.days_since(NOW.replace(day=1)), 0) == 14
    assert ctx.days_since(None) is None


def test_arns_are_built_from_the_identity():
    ctx = make_context()
    assert ctx.arn("ec2", "eu-west-1", "volume/vol-1") == (
        "arn:aws:ec2:eu-west-1:123456789012:volume/vol-1"
    )


def test_metrics_with_nothing_to_fetch_make_no_calls():
    def read(ctx):
        assert ctx.metrics("us-east-1", []) == {}
        return ()

    ctx = make_context()
    assert (
        run_check(ctx, check_that(read, actions=("cloudwatch:GetMetricStatistics",))).status
        == "ran"
    )


def test_metric_requests_carry_their_key_back():
    responses = {"get_metric_statistics": {"Datapoints": [{"Timestamp": NOW, "Sum": 3.0}]}}

    def read(ctx):
        series = ctx.metrics(
            "us-east-1",
            [
                MetricRequest(
                    key="a",
                    namespace="AWS/EC2",
                    metric="CPUUtilization",
                    dimensions={"InstanceId": "i-1"},
                    statistics=("Sum",),
                )
            ],
        )
        assert series["a"].total("Sum") == 3.0
        return ()

    ctx = make_context(responses)
    assert (
        run_check(ctx, check_that(read, actions=("cloudwatch:GetMetricStatistics",))).status
        == "ran"
    )


def test_the_context_defaults_to_now():
    ctx = ScanContext(make_context().session, regions=("us-east-1",))
    assert (datetime.now(UTC) - ctx.now).total_seconds() < 5
