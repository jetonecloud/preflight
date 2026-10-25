"""Running checks against an account.

`ScanContext` is the only thing a check is handed. It owns the credentials,
the clients, the time window and the price book, and it is also where the
permission contract is enforced: `collect` refuses to make a call the running
check didn't declare, so the role Preflight generates and the calls Preflight
makes can't drift apart.

The runner's other job is being honest about gaps. A check that hits a
missing permission is recorded as *skipped, because of this action*, not
quietly dropped; a region that won't answer is noted and the scan carries on.
A report that admits what it couldn't see is worth more than one that implies
it saw everything.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from preflight.core import metrics
from preflight.core.findings import Finding
from preflight.core.pricing import PriceBook

if TYPE_CHECKING:  # pragma: no cover - typing only
    from preflight.core.session import AwsSession, Identity
    from preflight.modules.base import Check, Module

# `core` never imports `modules` at runtime, only for types. The checks live
# in `modules` and import this file, so a runtime edge the other way would be
# a cycle — and the layering is right as it is: the runner doesn't need to
# know which modules exist, only how to run one it's handed.

# botocore is imported inside the functions that need it, never at the top of
# a module a check imports. Generating an IAM role must not load an AWS SDK —
# that's the promise `tests/test_cli_scan.py` holds this code to — and the
# checks are declared on the same import path the generator walks.

#: How far back the usage-based checks look by default. Two weeks is long
#: enough to cover a quiet fortnight without reaching back past the last
#: deploy, and short enough that a resource created last week still has data.
DEFAULT_LOOKBACK_DAYS = 14

#: Tag reads are an optional nicety: they put a name and an owner next to a
#: finding. Being denied this one degrades the report rather than stopping it.
TAG_ACTION = "tag:GetResources"

#: Looked up through the context like any other call, so a check that prices
#: something has to have declared it.
PRICING_ACTION = "pricing:GetProducts"


class UndeclaredAction(RuntimeError):
    """A check tried to call something it didn't declare.

    This is a bug in the check, not a problem with the account, and it's
    raised rather than worked around: the declaration is what the user read
    before deploying the role, so it has to be the whole truth.
    """

    def __init__(self, check: str, action: str) -> None:
        super().__init__(
            f"check '{check}' called {action}, which it does not declare. "
            f"Add it to the check's actions and to the module's iam_actions."
        )


class ScanContext:
    """Everything a check is allowed to touch."""

    def __init__(
        self,
        session: AwsSession,
        *,
        regions: Sequence[str],
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        now: datetime | None = None,
        prices: PriceBook | None = None,
    ) -> None:
        self.session = session
        self.regions: tuple[str, ...] = tuple(regions)
        self.lookback_days = lookback_days
        self.now = now or datetime.now(UTC)
        self.prices = prices or PriceBook(self._pricing_client)
        #: Things the report should admit to: denied extras, skipped regions,
        #: prices we couldn't look up. Deduplicated, in the order they happened.
        self.notes: list[str] = []
        self.unreadable_regions: dict[str, str] = {}
        self._allowed: frozenset[str] = frozenset()
        self._current: str = "<none>"
        self._examined: int = 0
        self._tags: dict[str, Mapping[str, Mapping[str, str]]] = {}
        self._reads: dict[tuple[Any, ...], list[dict[str, Any]]] = {}

    # --- the window -------------------------------------------------------

    @property
    def start(self) -> datetime:
        return self.now - timedelta(days=self.lookback_days)

    @property
    def end(self) -> datetime:
        return self.now

    def days_since(self, moment: Any) -> float | None:
        """Days between a timestamp and now, or `None` if it isn't one."""
        parsed = parse_timestamp(moment)
        if parsed is None:
            return None
        return (self.now - parsed).total_seconds() / 86400

    # --- identity ---------------------------------------------------------

    @property
    def identity(self) -> Identity:
        return self.session.identity

    @property
    def account_id(self) -> str:
        return self.identity.account_id

    def arn(self, service: str, region: str, resource: str) -> str:
        """Build an ARN for a resource whose API didn't hand us one."""
        return f"arn:{self.identity.partition}:{service}:{region}:{self.account_id}:{resource}"

    # --- reading AWS ------------------------------------------------------

    def collect(
        self,
        action: str,
        key: str,
        *,
        region: str | None = None,
        client: str | None = None,
        cache: bool = True,
        **params: Any,
    ) -> list[dict[str, Any]]:
        """Every item from a list/describe call, paginated.

        Identical calls are answered from a per-scan cache: several checks
        want the same list of volumes, and a scan is a point in time anyway,
        so reading it twice would only cost the user API calls. Pass
        `client` where boto3's name for a service doesn't follow the IAM
        prefix — the Classic load balancer API is `elb`, but the permission
        is still `elasticloadbalancing:DescribeLoadBalancers`.

        Returns an empty list for a region that won't answer, after noting
        it. Lets `MissingPermission` through, because a check missing one of
        its own permissions has nothing useful left to say.
        """
        from preflight.core import aws

        self._require(action)
        key_tuple = (action, key, region, client, repr(sorted(params.items())))
        if cache and key_tuple in self._reads:
            return self._reads[key_tuple]
        try:
            items = aws.collect(
                self.session.client(client or aws.service_of(action), region),
                action,
                key,
                region=region,
                **params,
            )
        except aws.RegionUnavailable as exc:
            self._region_failed(region or self.session.home_region, exc.message)
            items = []
        if cache:
            self._reads[key_tuple] = items
        return items

    def call(
        self,
        action: str,
        *,
        region: str | None = None,
        client: str | None = None,
        **params: Any,
    ) -> dict[str, Any]:
        """A single call, same rules as `collect` but without the cache."""
        from preflight.core import aws

        self._require(action)
        try:
            return aws.call(
                self.session.client(client or aws.service_of(action), region),
                action,
                region=region,
                **params,
            )
        except aws.RegionUnavailable as exc:
            self._region_failed(region or self.session.home_region, exc.message)
            return {}

    def metrics(
        self, region: str, requests: Sequence[metrics.MetricRequest]
    ) -> dict[str, metrics.MetricSeries]:
        """Fetch CloudWatch series for one region, in parallel."""
        from preflight.core import aws

        if not requests:
            return {}
        self._require(metrics.ACTION)
        try:
            return metrics.fetch(
                self.session.client("cloudwatch", region),
                requests,
                start=self.start,
                end=self.end,
                region=region,
            )
        except aws.RegionUnavailable as exc:
            self._region_failed(region, exc.message)
            return {}

    def _pricing_client(self) -> Any:
        """The pricing client, but only for a check that declared the action."""
        self._require(PRICING_ACTION)
        return self.session.client("pricing")

    def tags_for(self, region: str, arn: str) -> Mapping[str, str]:
        """Tags for a resource whose own API doesn't return them.

        Never raises: if `tag:GetResources` wasn't granted the report loses
        owner names, which is a smaller loss than losing the finding.
        """
        return self._tag_index(region).get(arn, {})

    def _tag_index(self, region: str) -> Mapping[str, Mapping[str, str]]:
        from preflight.core import aws

        if region in self._tags:
            return self._tags[region]
        index: dict[str, Mapping[str, str]] = {}
        if TAG_ACTION in self._allowed:
            try:
                for item in aws.collect(
                    self.session.client(aws.service_of(TAG_ACTION), region),
                    TAG_ACTION,
                    "ResourceTagMappingList",
                    region=region,
                ):
                    arn = str(item.get("ResourceARN", ""))
                    if arn:
                        index[arn] = {
                            str(tag.get("Key")): str(tag.get("Value"))
                            for tag in item.get("Tags", ())
                        }
            except aws.AwsError as exc:
                self.note(
                    f"Couldn't read resource tags ({exc.message}). Findings will "
                    "still be listed, but without owner names."
                )
        self._tags[region] = index
        return index

    # --- bookkeeping ------------------------------------------------------

    def note(self, text: str) -> None:
        """Record something the report should admit to. Deduplicated."""
        if text not in self.notes:
            self.notes.append(text)

    def _region_failed(self, region: str, reason: str) -> None:
        if region not in self.unreadable_regions:
            self.unreadable_regions[region] = reason
            self.note(f"{region} couldn't be read ({reason}), so it isn't covered below.")

    def _require(self, action: str) -> None:
        if action not in self._allowed:
            raise UndeclaredAction(self._current, action)

    def looked_at(self, count: int = 1) -> None:
        """Count resources the running check considered.

        The report shows this next to the findings — "142 volumes, 3 worth
        looking at" reads very differently from "3 findings", and it's the
        difference between a reader believing the quiet checks and not.
        """
        self._examined += count

    def begin_check(self, check: Check) -> None:
        """Called by the runner: from here on, only this check's actions."""
        self._current = check.key
        self._allowed = frozenset(check.actions) | {TAG_ACTION}
        self._examined = 0

    def end_check(self) -> None:
        """Close the window. Nothing can read anything between checks."""
        self._current = "<none>"
        self._allowed = frozenset()

    @property
    def examined(self) -> int:
        return self._examined


# --- outcomes -------------------------------------------------------------


@dataclass(frozen=True)
class CheckOutcome:
    """What happened when one check ran."""

    check: Check
    status: str  # "ran" | "skipped" | "failed"
    findings: tuple[Finding, ...] = ()
    reason: str | None = None
    missing_action: str | None = None
    examined: int = 0
    seconds: float = 0.0

    @property
    def ran(self) -> bool:
        return self.status == "ran"

    @property
    def clean(self) -> bool:
        """Ran, looked at something, and found nothing wrong."""
        return self.ran and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.check.key,
            "title": self.check.title,
            "looks_for": self.check.looks_for,
            "status": self.status,
            "findings": len(self.findings),
            "resources_examined": self.examined,
            "reason": self.reason,
            "missing_action": self.missing_action,
            "actions": list(self.check.actions),
            "seconds": round(self.seconds, 2),
        }


@dataclass
class ScanProgress:
    """Hooks the CLI draws progress with. Defaults to doing nothing."""

    on_check_start: Callable[[Check], None] = lambda check: None
    on_check_done: Callable[[CheckOutcome], None] = lambda outcome: None


def run_module(
    ctx: ScanContext,
    module: Module,
    *,
    progress: ScanProgress | None = None,
    only: Sequence[str] | None = None,
) -> list[CheckOutcome]:
    """Run a module's checks in order and collect what each one did."""
    progress = progress or ScanProgress()
    wanted = set(only) if only else None
    outcomes: list[CheckOutcome] = []
    for check in module.checks:
        if wanted is not None and check.key not in wanted:
            continue
        progress.on_check_start(check)
        outcome = run_check(ctx, check)
        outcomes.append(outcome)
        progress.on_check_done(outcome)
    return outcomes


def run_check(ctx: ScanContext, check: Check) -> CheckOutcome:
    """Run one check, converting any failure into a reportable outcome.

    `MissingPermission` is the interesting case: the check is marked skipped
    and the action is kept, so the summary can tell the user exactly which
    line to add to the role rather than "something went wrong".
    """
    from preflight.core import aws

    ctx.begin_check(check)
    started = time.monotonic()

    def elapsed() -> float:
        return time.monotonic() - started

    try:
        findings = tuple(check.run(ctx))
    except aws.MissingPermission as exc:
        return CheckOutcome(
            check,
            "skipped",
            reason=f"the role can't call {exc.action}",
            missing_action=exc.action,
            examined=ctx.examined,
            seconds=elapsed(),
        )
    except aws.NotSubscribed as exc:
        return CheckOutcome(check, "skipped", reason=exc.message, seconds=elapsed())
    except aws.CredentialsError:
        # Nothing else will work either — let this one end the scan.
        raise
    except aws.AwsError as exc:
        return CheckOutcome(
            check, "failed", reason=exc.message, examined=ctx.examined, seconds=elapsed()
        )
    else:
        return CheckOutcome(check, "ran", findings, examined=ctx.examined, seconds=elapsed())
    finally:
        ctx.end_check()


# --- small helpers the checks share ---------------------------------------


def tags_to_dict(tags: Iterable[Mapping[str, Any]] | None) -> dict[str, str]:
    """`[{"Key": "Name", "Value": "web"}]` -> `{"Name": "web"}`."""
    return {str(tag.get("Key")): str(tag.get("Value", "")) for tag in tags or () if tag.get("Key")}


def name_of(tags: Mapping[str, str]) -> str | None:
    return tags.get("Name") or tags.get("name") or None


#: Tag a resource with any of these and Preflight leaves it alone. The
#: escape hatch matters: the second time a report tells you about the
#: snapshot you're deliberately keeping, you stop reading the report.
IGNORE_TAGS: tuple[str, ...] = ("preflight:ignore", "preflight-ignore", "PreflightIgnore")

#: Values that mean "no, don't ignore this after all", so the tag can be left
#: in place and switched off.
NEGATIVE = frozenset({"false", "no", "0", "off"})


def ignored(tags: Mapping[str, str]) -> bool:
    """Whether the owner has asked Preflight to skip this resource."""
    for key in IGNORE_TAGS:
        if key in tags and str(tags[key]).strip().lower() not in NEGATIVE:
            return True
    return False


def parse_timestamp(value: Any) -> datetime | None:
    """A timezone-aware datetime out of whatever the API returned.

    boto3 hands back aware datetimes, but fixtures, cached JSON and the demo
    data use strings, and a naive datetime compared against an aware one
    raises rather than returning a wrong answer — which is worse here,
    because it would take out a whole check over a formatting detail.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
