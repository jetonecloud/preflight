"""What every reliability check has to decide the same way.

Mostly: is this production? A single-AZ database in a sandbox is a sensible
saving, and a report that says otherwise teaches people to stop reading it.
Preflight can't know for sure, so it believes a tag when there is one and
hedges when there isn't.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from preflight.core.findings import Confidence, Severity
from preflight.core.scan import ScanContext

MODULE = "reliability"

#: One thing wrong with a resource: (severity, title, evidence, the step
#: that fixes it). A resource with several gets one finding, led by the worst.
Problem = tuple[Severity, str, str, str]

#: Something created this week may still be being set up.
MIN_RESOURCE_AGE_DAYS = 7

#: Tag keys people use to say which environment something belongs to.
ENVIRONMENT_KEYS: tuple[str, ...] = (
    "Environment",
    "environment",
    "Env",
    "env",
    "Stage",
    "stage",
    "Tier",
    "tier",
)

#: Values that mean "this is allowed to fall over".
NON_PRODUCTION = frozenset(
    {
        "dev",
        "development",
        "test",
        "testing",
        "qa",
        "staging",
        "stage",
        "sandbox",
        "demo",
        "preview",
        "experiment",
        "scratch",
    }
)

#: Values that mean "people depend on this".
PRODUCTION = frozenset({"prod", "production", "live", "prd"})


def environment(tags: Mapping[str, str]) -> str | None:
    """The environment a tag names, lower-cased, if any tag names one."""
    for key in ENVIRONMENT_KEYS:
        value = tags.get(key)
        if value and value.strip():
            return value.strip().lower()
    return None


def non_production(tags: Mapping[str, str]) -> bool:
    """Whether a tag says this is allowed to fall over."""
    return environment(tags) in NON_PRODUCTION


def confidence_for(tags: Mapping[str, str]) -> Confidence:
    """High when a tag says production, medium when nothing says either way."""
    return Confidence.HIGH if environment(tags) in PRODUCTION else Confidence.MEDIUM


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
