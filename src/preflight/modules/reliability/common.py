"""What every reliability check has to decide the same way.

Mostly: is this production? That question is shared with the other modules
that judge by environment, so the answer lives in `modules.environment` and
is re-exported here for the checks that already import it from this file.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from preflight.core.findings import Severity
from preflight.core.scan import ScanContext
from preflight.modules.environment import (
    ENVIRONMENT_KEYS,
    NON_PRODUCTION,
    PRODUCTION,
    confidence_for,
    environment,
    non_production,
)

MODULE = "reliability"

#: One thing wrong with a resource: (severity, title, evidence, the step
#: that fixes it). A resource with several gets one finding, led by the worst.
Problem = tuple[Severity, str, str, str]

#: Something created this week may still be being set up.
MIN_RESOURCE_AGE_DAYS = 7


def too_new(ctx: ScanContext, created: Any) -> bool:
    """Created this week: give it time to be finished."""
    age = ctx.days_since(created)
    return age is not None and age < MIN_RESOURCE_AGE_DAYS


def environment_caveat(tags: Mapping[str, str]) -> str | None:
    """A line for the evidence when the environment had to be guessed."""
    if environment(tags) in PRODUCTION:
        return None
    return (
        "Nothing tags it as production or otherwise. If it isn't production, "
        "tag it Environment=dev and the reliability checks will leave it alone."
    )


__all__ = [
    "ENVIRONMENT_KEYS",
    "MIN_RESOURCE_AGE_DAYS",
    "MODULE",
    "NON_PRODUCTION",
    "PRODUCTION",
    "Problem",
    "confidence_for",
    "environment",
    "environment_caveat",
    "non_production",
    "too_new",
]
