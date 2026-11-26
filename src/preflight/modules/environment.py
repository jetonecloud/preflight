"""Is this production? What every module that judges by environment shares.

A single-AZ database in a sandbox is a sensible saving, and a service in a
preview environment pulling `:latest` is how previews work. A report that
says otherwise teaches people to stop reading it. Preflight can't know for
sure, so it believes a tag when there is one and hedges when there isn't.
"""

from __future__ import annotations

from collections.abc import Mapping

from preflight.core.findings import Confidence

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


def production(tags: Mapping[str, str]) -> bool:
    """Whether a tag says people depend on this."""
    return environment(tags) in PRODUCTION


def confidence_for(tags: Mapping[str, str]) -> Confidence:
    """High when a tag says production, medium when nothing says either way."""
    return Confidence.HIGH if production(tags) else Confidence.MEDIUM
