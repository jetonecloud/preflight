"""Turning AWS failures into something a person can act on.

Every call a check makes goes through here, so there is one place that knows
what `AccessDeniedException` means and one place that decides what to tell
the user about it. The rule: a check that can't read what it needs is
*skipped and reported as skipped* — never silently downgraded into a
half-answer, because a cost report that quietly omits a region is worse than
one that admits it couldn't look.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from botocore import xform_name
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)


class AwsError(Exception):
    """Something went wrong talking to AWS, phrased for the person running it."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        self.message = message
        self.hint = hint
        super().__init__(message)


class CredentialsError(AwsError):
    """We couldn't authenticate at all — nothing was read."""


class MissingPermission(AwsError):
    """The identity can't perform an action a check needs.

    Carries the action so the report can name it, and so the user can
    regenerate a role that includes it instead of guessing.
    """

    def __init__(self, action: str, region: str | None = None) -> None:
        self.action = action
        self.region = region
        where = f" in {region}" if region else ""
        super().__init__(
            f"not allowed to call {action}{where}",
            hint=f"Add {action} to the role, or re-run without the check that needs it.",
        )


class NotSubscribed(AwsError):
    """The API is there but this account hasn't enabled it (Cost Explorer, say)."""

    def __init__(self, action: str) -> None:
        self.action = action
        super().__init__(f"{action} isn't enabled for this account")


class RegionUnavailable(AwsError):
    """A region we tried to read isn't enabled, or wouldn't answer."""

    def __init__(self, region: str, reason: str) -> None:
        self.region = region
        super().__init__(f"couldn't read {region}: {reason}")


#: Error codes that mean "you are not allowed to do that".
DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthorizationError",
        "AuthorizationErrorException",
        "Client.UnauthorizedOperation",
        "UnauthorizedOperation",
        "DataUnavailableException",
        "NotAuthorized",
    }
)

#: Error codes that mean the credentials themselves are the problem.
CREDENTIAL_CODES = frozenset(
    {
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "RequestExpired",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
        "InvalidAccessKeyId",
    }
)

#: Error codes that mean this region isn't available to the account.
REGION_CODES = frozenset({"OptInRequired", "AuthFailure", "UnrecognizedClientException"})

EXPIRED_HINT = "Your credentials have expired. Log in again (for example: aws sso login)."


def code_of(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", ""))


def message_of(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Message", "")).strip()


def translate(error: Exception, *, action: str, region: str | None = None) -> AwsError:
    """Map a boto3 exception onto one of ours, keeping the action in view."""
    if isinstance(error, ClientError):
        code = code_of(error)
        if code in DENIED_CODES:
            return MissingPermission(action, region)
        if code in CREDENTIAL_CODES:
            return CredentialsError(f"{action} failed: {message_of(error) or code}", EXPIRED_HINT)
        if code == "SubscriptionRequiredException":
            return NotSubscribed(action)
        if code in REGION_CODES and region:
            return RegionUnavailable(region, message_of(error) or code)
        return AwsError(f"{action} failed ({code}): {message_of(error) or 'no detail given'}")
    if isinstance(error, NoCredentialsError):
        return CredentialsError(
            "No AWS credentials found.",
            "Log in the way you normally do (aws sso login, or --profile <name>).",
        )
    if isinstance(error, EndpointConnectionError) and region:
        return RegionUnavailable(region, "couldn't reach the endpoint")
    if isinstance(error, (BotoCoreError, OSError)):
        return AwsError(f"{action} failed: {error}")
    return AwsError(f"{action} failed: {type(error).__name__}: {error}")


def method_name(action: str) -> str:
    """`rds:DescribeDBInstances` -> `describe_db_instances`.

    Uses botocore's own name transform, which is what generated the client's
    methods in the first place, so the irregular ones (`DescribeDBInstances`)
    come out right without a lookup table.
    """
    return xform_name(action.split(":", 1)[1])


def service_of(action: str) -> str:
    """The IAM service prefix: `elasticloadbalancing` for a load balancer call."""
    return action.split(":", 1)[0]


def collect(
    client: Any,
    action: str,
    key: str,
    *,
    region: str | None = None,
    **params: Any,
) -> list[dict[str, Any]]:
    """Run a list/describe call to completion and return the items.

    Paginates when the operation supports it, because the first page of
    `DescribeVolumes` on a real account is never the whole story.
    """
    return list(iterate(client, action, key, region=region, **params))


def iterate(
    client: Any,
    action: str,
    key: str,
    *,
    region: str | None = None,
    **params: Any,
) -> Iterator[dict[str, Any]]:
    method = method_name(action)
    try:
        if client.can_paginate(method):
            pages: Any = client.get_paginator(method).paginate(**params)
        else:
            pages = [getattr(client, method)(**params)]
        for page in pages:
            yield from page.get(key, ())
    except (ClientError, BotoCoreError, OSError) as exc:
        raise translate(exc, action=action, region=region) from exc


def call(client: Any, action: str, *, region: str | None = None, **params: Any) -> dict[str, Any]:
    """A single non-paginated call, with the same error translation."""
    try:
        return getattr(client, method_name(action))(**params)
    except (ClientError, BotoCoreError, OSError) as exc:
        raise translate(exc, action=action, region=region) from exc


def profile_error(error: ProfileNotFound, profile: str) -> CredentialsError:
    return CredentialsError(
        f"There's no AWS profile called '{profile}'.",
        "Check `aws configure list-profiles` for the ones you have.",
    )


def region_error(error: NoRegionError) -> CredentialsError:
    return CredentialsError(
        "No AWS region configured.",
        "Pass --region us-east-1, or set one with `aws configure`.",
    )
