"""CloudFormation stacks that can't be deployed, or don't describe what's running.

Infrastructure as code is only worth having while the code is the truth.
Two things quietly end that. A stack stuck after a failed rollback refuses
every update until someone untangles it by hand - usually discovered in
the middle of an incident, when the fix needs deploying. And a stack that
has drifted means someone changed a resource in the console: the next
deploy will either undo their change or fail on it.

Preflight never starts drift detection - that's a write, and it isn't
asking for those. It reports what the last detection found, and says how
long ago that was.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored, tags_to_dict
from preflight.modules.base import Check
from preflight.modules.delivery.common import MODULE, Problem, recommendation, worst_first

#: The stack can't be updated until someone intervenes. Rollback failed
#: means resources may be half-changed; the others mean the stack is a
#: shell that can only be deleted.
STUCK: dict[str, tuple[Severity, str, str]] = {
    "UPDATE_ROLLBACK_FAILED": (
        Severity.HIGH,
        "An update failed and so did the rollback, so its resources may be half "
        "changed and CloudFormation will refuse every update until it's resolved.",
        "continue the rollback (skipping the resources that block it), then redeploy",
    ),
    "ROLLBACK_FAILED": (
        Severity.MEDIUM,
        "It failed to create, and failed to clean up after itself: some resources "
        "may still exist outside any working stack.",
        "delete it, checking for anything it leaves behind, and create it again",
    ),
    "ROLLBACK_COMPLETE": (
        Severity.MEDIUM,
        "It failed to create and was rolled back. A stack in this state can't be "
        "updated, only deleted, so the next deploy to this name will fail.",
        "delete it and create it again",
    ),
    "DELETE_FAILED": (
        Severity.MEDIUM,
        "Someone tried to delete it and couldn't. Whatever blocked the delete is "
        "still there, and so is the stack.",
        "find the resource that blocked the delete, then finish deleting it",
    ),
    "IMPORT_ROLLBACK_FAILED": (
        Severity.MEDIUM,
        "A resource import failed, and so did its rollback.",
        "resolve the import, or remove the imported resources from the template",
    ),
}

#: A failure from the last day is probably still being dealt with.
FRESH_FAILURE_DAYS = 1

#: Drift detected longer ago than this may have been fixed since.
STALE_DRIFT_DAYS = 30

#: How many drifted resources to name before summarising the rest.
NAMED_RESOURCES = 3


def cloudformation_stacks_at_risk(ctx: ScanContext) -> Iterator[Finding]:
    """Stacks stuck in a failed state, and stacks whose resources have drifted."""
    for region in ctx.regions:
        for stack in ctx.collect("cloudformation:DescribeStacks", "Stacks", region=region):
            finding = _judge(ctx, region, stack)
            if finding is not None:
                yield finding


def _judge(ctx: ScanContext, region: str, stack: dict[str, Any]) -> Finding | None:
    status = str(stack.get("StackStatus", ""))
    if status == "DELETE_COMPLETE":
        return None
    ctx.looked_at()
    tags = tags_to_dict(stack.get("Tags"))
    if ignored(tags):
        return None

    problems: list[Problem] = []
    stuck = _stuck(ctx, stack, status)
    if stuck is not None:
        problems.append(stuck)
    drift = _drift(ctx, region, stack)
    if drift is not None:
        problems.append(drift)
    if not problems:
        return None
    return _finding(ctx, region, stack, tags, worst_first(problems))


def _stuck(ctx: ScanContext, stack: dict[str, Any], status: str) -> Problem | None:
    if status not in STUCK:
        return None
    if stack.get("ParentId"):
        # A nested stack fails with its parent, which is where it's fixed.
        return None
    changed = stack.get("LastUpdatedTime") or stack.get("CreationTime")
    age = ctx.days_since(changed)
    if age is not None and age < FRESH_FAILURE_DAYS:
        return None
    severity, evidence, step = STUCK[status]
    if age is not None:
        evidence = f"{evidence} It has been {status} for {_days(age)}."
    return (severity, "CloudFormation stack stuck after a failed deploy", evidence, step)


def _drift(ctx: ScanContext, region: str, stack: dict[str, Any]) -> Problem | None:
    info = stack.get("DriftInformation") or {}
    if info.get("StackDriftStatus") != "DRIFTED":
        return None
    drifted = ctx.collect(
        "cloudformation:DescribeStackResourceDrifts",
        "StackResourceDrifts",
        region=region,
        StackName=str(stack.get("StackId") or stack.get("StackName")),
        StackResourceDriftStatusFilters=["MODIFIED", "DELETED"],
    )
    evidence = "Its last drift detection found resources changed outside CloudFormation"
    named = [
        f"{item.get('LogicalResourceId')} ({str(item.get('StackResourceDriftStatus', '')).lower()})"
        for item in drifted[:NAMED_RESOURCES]
    ]
    if named:
        more = len(drifted) - len(named)
        evidence += ": " + ", ".join(named) + (f" and {more} more" if more > 0 else "")
    evidence += ". The next deploy will undo those changes, or fail on them."
    age = ctx.days_since(info.get("LastCheckTimestamp"))
    if age is not None and age > STALE_DRIFT_DAYS:
        evidence += f" That detection ran {_days(age)} ago, so it may have been put right since."
    return (
        Severity.MEDIUM,
        "CloudFormation stack has drifted from its template",
        evidence,
        "fold the changes into the template, or redeploy to put the resources back, "
        "then run drift detection again",
    )


def _days(age: float) -> str:
    days = int(age)
    return "a day" if days == 1 else f"{days} days"


def _finding(
    ctx: ScanContext,
    region: str,
    stack: dict[str, Any],
    tags: dict[str, str],
    problems: list[Problem],
) -> Finding:
    name = str(stack.get("StackName"))
    severity, title, _, _ = problems[0]
    evidence = [f"Stack {name} ({stack.get('StackStatus')})."]
    evidence.extend(line for _, _, line, _ in problems)
    drift_only = all(problem[1].endswith("drifted from its template") for problem in problems)
    age = ctx.days_since((stack.get("DriftInformation") or {}).get("LastCheckTimestamp"))
    stale = drift_only and age is not None and age > STALE_DRIFT_DAYS
    return Finding(
        check="cloudformation-stacks-at-risk",
        module=MODULE,
        title=title,
        resource=Resource(
            id=name,
            kind="cloudformation:stack",
            region=region,
            arn=stack.get("StackId") or ctx.arn("cloudformation", region, f"stack/{name}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=recommendation(problems),
        confidence=Confidence.MEDIUM if stale else Confidence.HIGH,
        severity=severity,
    )


CLOUDFORMATION_STACKS_AT_RISK = Check(
    key="cloudformation-stacks-at-risk",
    title="CloudFormation stacks you can't deploy with confidence",
    looks_for=(
        "Stacks stuck after a failed create, update or delete, and stacks whose last "
        "drift detection found resources changed by hand."
    ),
    actions=(
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResourceDrifts",
    ),
    run=cloudformation_stacks_at_risk,
)
