"""A fake AWS, so the checks can be tested on their judgement.

The checks are mostly judgement — is this idle, is this safe to flag, is
this actually a false positive — and judgement is best tested against data
you can see in one screen. These stubs answer the handful of calls
`core.aws` makes and nothing else, which keeps a test about stale snapshots
to a list of stale snapshots.

Error paths get the real thing: `ClientError` is constructed exactly as
botocore builds it, so the code under test can't pass by being lenient with
a shape the SDK never produces.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from botocore.exceptions import ClientError

from preflight.core.scan import ScanContext, run_check
from preflight.core.session import AwsSession, Identity

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

IDENTITY = Identity(
    account_id=ACCOUNT_ID,
    arn=f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/PreflightReadOnlyRole/preflight-scan",
    user_id="AROATEST:preflight-scan",
)

NOW = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)


def days_ago(days: float, now: datetime = NOW) -> datetime:
    return now - timedelta(days=days)


def denied(operation: str, code: str = "AccessDeniedException") -> ClientError:
    """The error AWS returns when the role is missing a permission."""
    return ClientError(
        {"Error": {"Code": code, "Message": f"not authorized to perform {operation}"}},
        operation,
    )


def tags(**pairs: str) -> list[dict[str, str]]:
    return [{"Key": key, "Value": value} for key, value in pairs.items()]


def datapoints(values: list[float], statistic: str = "Sum") -> dict[str, Any]:
    """A CloudWatch response with one datapoint per value."""
    return {
        "Datapoints": [
            {"Timestamp": days_ago(index), statistic: value, "Average": value}
            for index, value in enumerate(values)
        ]
    }


class StubClient:
    """Answers the boto3 methods `core.aws` calls, from a dict.

    A value can be a response dict, a callable taking the request kwargs, or
    an exception to raise — which is how the permission-denied paths get
    tested without a network.
    """

    def __init__(self, responses: dict[str, Any], service: str = "", region: str = REGION) -> None:
        self._responses = responses
        self.service = service
        self.region = region
        #: Every call made, so a test can assert what was and wasn't read.
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def can_paginate(self, _method: str) -> bool:
        return False

    def __getattr__(self, method: str) -> Any:
        def call(**params: Any) -> dict[str, Any]:
            self.calls.append((method, params))
            answer = self._responses.get(method, {})
            if isinstance(answer, BaseException):
                raise answer
            if callable(answer):
                return answer(**params)
            return answer

        return call


class StubSession(AwsSession):
    """A real `AwsSession` with the client factory swapped out.

    Subclassed rather than reimplemented so that everything built on top of
    a session — region discovery, identity, the error translation — is the
    code that ships, not a second copy of it written to agree with the tests.
    """

    def __init__(
        self,
        responses: dict[str, Any] | None = None,
        *,
        identity: Identity = IDENTITY,
        home_region: str = REGION,
        per_service: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(None, home_region=home_region, source="a stub")
        self._identity = identity
        self._responses = responses or {}
        self._per_service = per_service or {}
        self.clients: dict[tuple[str, str], StubClient] = {}

    def client(self, service: str, region: str | None = None) -> StubClient:
        where = region or self.home_region
        key = (service, where)
        if key not in self.clients:
            responses = dict(self._responses)
            responses.update(self._per_service.get(service, {}))
            self.clients[key] = StubClient(responses, service=service, region=where)
        return self.clients[key]


def make_context(
    responses: dict[str, Any] | None = None,
    *,
    regions: tuple[str, ...] = (REGION,),
    lookback_days: int = 14,
    now: datetime = NOW,
    session: StubSession | None = None,
    **kwargs: Any,
) -> ScanContext:
    session = session or StubSession(responses, **kwargs)
    return ScanContext(session, regions=regions, lookback_days=lookback_days, now=now)


def run(check: Any, responses: dict[str, Any] | None = None, **kwargs: Any) -> Any:
    """Run one check against stub data and return its outcome."""
    return run_check(make_context(responses, **kwargs), check)


def findings(check: Any, responses: dict[str, Any] | None = None, **kwargs: Any) -> tuple[Any, ...]:
    """Just the findings, for the common case."""
    outcome = run(check, responses, **kwargs)
    assert outcome.status == "ran", f"{check.key} didn't run: {outcome.reason}"
    return outcome.findings


@pytest.fixture
def now() -> datetime:
    return NOW
