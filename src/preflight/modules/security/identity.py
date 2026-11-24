"""Who can get into the account, and how easily.

IAM is global, so these checks read it once from the home region and report
against `global` rather than a region. Nothing here prices anything: a root
user without MFA doesn't cost a dollar a month until the day it costs the
company.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext
from preflight.modules.base import Check

MODULE = "security"

#: IAM isn't in a region. Findings about it say so rather than pretend.
GLOBAL = "global"


# --- the root user ---------------------------------------------------------


def root_user_unguarded(ctx: ScanContext) -> Iterator[Finding]:
    """The root user with no MFA, or with access keys of its own."""
    summary: dict[str, Any] = ctx.call("iam:GetAccountSummary").get("SummaryMap") or {}
    if not summary:
        return
    ctx.looked_at()

    no_mfa = summary.get("AccountMFAEnabled") == 0
    has_keys = bool(summary.get("AccountAccessKeysPresent"))
    if not (no_mfa or has_keys):
        return

    evidence: list[str] = []
    steps: list[str] = []
    if no_mfa:
        evidence.append(
            "The root user has no MFA device: its email address and password are "
            "all it takes to sign in, and root can do anything - including close "
            "the account."
        )
        steps.append("add an MFA device to the root user (a hardware key, ideally two)")
    if has_keys:
        evidence.append(
            "The root user has access keys. Anything holding them can call any API "
            "with no way to limit it, and they can't be scoped by a policy."
        )
        steps.append("delete the root access keys and give whatever used them an IAM role")

    if no_mfa and has_keys:
        title = "Root user with access keys and no MFA"
    elif no_mfa:
        title = "Root user without MFA"
    else:
        title = "Root user with access keys"

    yield Finding(
        check="root-user-unguarded",
        module=MODULE,
        title=title,
        resource=Resource(
            id="root",
            kind="iam:root-user",
            region=GLOBAL,
            arn=f"arn:{ctx.identity.partition}:iam::{ctx.account_id}:root",
        ),
        evidence=tuple(evidence),
        recommendation=(
            "Sign in as root once, " + ", and ".join(steps) + ". Then stop using it: "
            "day-to-day work belongs to IAM Identity Center users or roles."
        ),
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
    )


ROOT_USER_UNGUARDED = Check(
    key="root-user-unguarded",
    title="Root user unguarded",
    looks_for="A root user with no MFA, or with access keys of its own.",
    actions=("iam:GetAccountSummary",),
    run=root_user_unguarded,
)
