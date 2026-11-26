"""CloudFormation stacks you can't deploy with confidence."""

from __future__ import annotations

from conftest import StubSession, days_ago, denied, findings, make_context, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.core.scan import run_check
from preflight.modules.delivery.stacks import CLOUDFORMATION_STACKS_AT_RISK as CHECK

ACCOUNT = "123456789012"


def stack(name="api", status="UPDATE_COMPLETE", drift="IN_SYNC", checked=2, **extra):
    return {
        "StackName": name,
        "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{name}/abc",
        "StackStatus": status,
        "CreationTime": days_ago(200),
        "LastUpdatedTime": days_ago(20),
        "DriftInformation": {"StackDriftStatus": drift, "LastCheckTimestamp": days_ago(checked)},
        "Tags": [],
        **extra,
    }


def drifts(*resources):
    return [
        {"LogicalResourceId": logical, "StackResourceDriftStatus": status}
        for logical, status in resources
    ]


def account(*stacks, drifted=()):
    return {
        "describe_stacks": {"Stacks": list(stacks)},
        "describe_stack_resource_drifts": {"StackResourceDrifts": list(drifted)},
    }


def test_a_healthy_stack_in_sync_is_fine():
    outcome = run(CHECK, account(stack()))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_rollback_failed_on_update_is_high():
    (found,) = findings(CHECK, account(stack(status="UPDATE_ROLLBACK_FAILED")))
    assert found.title == "CloudFormation stack stuck after a failed deploy"
    assert found.level is Severity.HIGH
    assert found.confidence is Confidence.HIGH
    assert found.resource.kind == "cloudformation:stack"
    assert "for 20 days" in " ".join(found.evidence)
    assert found.recommendation.startswith("Continue the rollback")


def test_a_failed_create_is_a_stack_that_can_only_be_deleted():
    (found,) = findings(CHECK, account(stack(status="ROLLBACK_COMPLETE")))
    assert found.level is Severity.MEDIUM
    assert "only deleted" in " ".join(found.evidence)


def test_a_failure_from_today_is_left_to_whoever_is_on_it():
    fresh = stack(status="ROLLBACK_COMPLETE", LastUpdatedTime=days_ago(0.2))
    assert findings(CHECK, account(fresh)) == ()


def test_nested_stacks_are_fixed_through_their_parent():
    nested = stack(status="UPDATE_ROLLBACK_FAILED", ParentId="arn:parent")
    assert findings(CHECK, account(nested)) == ()


def test_drift_names_the_resources_that_changed():
    changed = drifts(("Database", "MODIFIED"), ("Queue", "DELETED"))
    (found,) = findings(CHECK, account(stack(drift="DRIFTED"), drifted=changed))
    assert found.title == "CloudFormation stack has drifted from its template"
    assert found.level is Severity.MEDIUM
    assert found.confidence is Confidence.HIGH
    assert "Database (modified), Queue (deleted)" in " ".join(found.evidence)


def test_drift_asks_only_for_changed_resources():
    session = StubSession(account(stack(drift="DRIFTED")))
    run_check(make_context(session=session), CHECK)
    asked = [
        params
        for client in session.clients.values()
        for method, params in client.calls
        if method == "describe_stack_resource_drifts"
    ]
    assert asked[0]["StackResourceDriftStatusFilters"] == ["MODIFIED", "DELETED"]


def test_many_drifted_resources_are_summarised():
    changed = drifts(*[(f"Thing{n}", "MODIFIED") for n in range(5)])
    (found,) = findings(CHECK, account(stack(drift="DRIFTED"), drifted=changed))
    assert "and 2 more" in " ".join(found.evidence)


def test_old_drift_results_are_hedged():
    (found,) = findings(CHECK, account(stack(drift="DRIFTED", checked=90)))
    assert found.confidence is Confidence.MEDIUM
    assert "90 days ago" in " ".join(found.evidence)


def test_never_checked_and_in_sync_stacks_say_nothing():
    unchecked = stack("a", drift="NOT_CHECKED")
    unknown = stack("b", drift="UNKNOWN")
    assert findings(CHECK, account(unchecked, unknown)) == ()


def test_stuck_and_drifted_is_one_finding_titled_by_the_worst():
    both = stack(status="UPDATE_ROLLBACK_FAILED", drift="DRIFTED")
    (found,) = findings(CHECK, account(both, drifted=drifts(("Db", "MODIFIED"))))
    assert found.level is Severity.HIGH
    assert found.title == "CloudFormation stack stuck after a failed deploy"
    assert "run drift detection again" in found.recommendation


def test_ignored_stacks_are_left_alone():
    quiet = stack(status="ROLLBACK_COMPLETE", Tags=tags(**{"preflight:ignore": "true"}))
    assert findings(CHECK, account(quiet)) == ()


def test_skipped_without_permission():
    outcome = run(CHECK, {"describe_stacks": denied("DescribeStacks")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "cloudformation:DescribeStacks"
