"""What every delivery check shares."""

from __future__ import annotations

from preflight.core.findings import Severity

MODULE = "delivery"

#: One thing wrong with a resource: (severity, title, evidence, the step
#: that fixes it). A resource with several gets one finding, led by the worst.
Problem = tuple[Severity, str, str, str]

#: Something created this week may still be being set up.
MIN_RESOURCE_AGE_DAYS = 7


def recommendation(problems: list[Problem]) -> str:
    """Every problem's fix, as one sentence."""
    steps = "; ".join(step for _, _, _, step in problems)
    return f"{steps[:1].upper()}{steps[1:]}."


def worst_first(problems: list[Problem]) -> list[Problem]:
    """Sorted so the finding is titled by its most severe problem."""
    return sorted(problems, key=lambda problem: problem[0].rank)
