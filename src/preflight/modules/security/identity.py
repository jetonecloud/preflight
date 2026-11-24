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
from preflight.core.scan import ScanContext, ignored, tags_to_dict
from preflight.modules.base import Check

MODULE = "security"

#: IAM isn't in a region. Findings about it say so rather than pretend.
GLOBAL = "global"

#: A user made this week may be setting up MFA right now. Give them a week
#: before saying anything - unless they've already signed in without it.
MIN_USER_AGE_DAYS = 7

#: Someone who has used their password this recently is a person signing in
#: today, not a forgotten account.
ACTIVE_SIGN_IN_DAYS = 90

#: An active key nobody has used in this long is a credential waiting to leak.
UNUSED_KEY_DAYS = 90

#: Past this, an unused key is high severity: whatever it was for is gone.
LONG_UNUSED_KEY_DAYS = 365

#: A key created this recently and not yet used may be on its way into a
#: deploy pipeline.
NEW_KEY_DAYS = 30

#: A key in use but older than this should have been rotated by now.
ROTATE_AFTER_DAYS = 365


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


# --- console users without MFA ---------------------------------------------


def console_users_without_mfa(ctx: ScanContext) -> Iterator[Finding]:
    """IAM users who can sign in to the console with only a password."""
    for user in ctx.collect("iam:ListUsers", "Users"):
        ctx.looked_at()
        name = str(user.get("UserName"))
        if not _has_password(ctx, name):
            continue
        if ctx.collect("iam:ListMFADevices", "MFADevices", UserName=name):
            continue

        last_sign_in = ctx.days_since(user.get("PasswordLastUsed"))
        age = ctx.days_since(user.get("CreateDate"))
        if last_sign_in is None and age is not None and age < MIN_USER_AGE_DAYS:
            continue

        tags = user_tags(ctx, name)
        if ignored(tags):
            continue

        evidence = ["Has a console password and no MFA device: the password alone signs in."]
        if last_sign_in is None:
            evidence.append("Has never signed in with it - a password nobody is using.")
        else:
            evidence.append(f"Last signed in with it {last_sign_in:,.0f} days ago.")
        if age is not None:
            evidence.append(f"The user was created {age:,.0f} days ago.")

        active = last_sign_in is not None and last_sign_in <= ACTIVE_SIGN_IN_DAYS
        yield Finding(
            check="console-users-without-mfa",
            module=MODULE,
            title="Console user without MFA" if active else "Unused console password, no MFA",
            resource=Resource(
                id=name,
                kind="iam:user",
                region=GLOBAL,
                arn=str(user.get("Arn") or "") or None,
                tags=tags,
            ),
            evidence=tuple(evidence),
            recommendation=(
                "Require MFA for this user, or move them to IAM Identity Center and "
                "delete the IAM user."
                if active
                else "Nobody is using this password: delete the login profile. If "
                "they do still need the console, give them MFA first."
            ),
            confidence=Confidence.HIGH,
            severity=Severity.HIGH if active else Severity.MEDIUM,
        )


def _has_password(ctx: ScanContext, user: str) -> bool:
    """Whether the user has a console password. IAM says `NoSuchEntity` if not."""
    from preflight.core import aws

    try:
        ctx.call("iam:GetLoginProfile", UserName=user)
    except aws.NotFound:
        return False
    return True


def user_tags(ctx: ScanContext, user: str) -> dict[str, str]:
    """A user's tags, which `ListUsers` leaves out and the tagging API can't see.

    Like every tag read, losing it costs the report owner names and the
    ignore tag, not the finding.
    """
    from preflight.core import aws

    try:
        return tags_to_dict(ctx.collect("iam:ListUserTags", "Tags", UserName=user))
    except aws.MissingPermission:
        ctx.note(
            "Couldn't read IAM user tags (iam:ListUserTags was denied), so "
            "'preflight:ignore' on a user can't be honoured."
        )
        return {}


CONSOLE_USERS_WITHOUT_MFA = Check(
    key="console-users-without-mfa",
    title="Console users without MFA",
    looks_for="IAM users who can sign in to the console with only a password.",
    actions=(
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListUserTags",
    ),
    run=console_users_without_mfa,
)


# --- access keys -----------------------------------------------------------


def stale_access_keys(ctx: ScanContext) -> Iterator[Finding]:
    """Active access keys nobody uses, and keys in use that were never rotated."""
    for user in ctx.collect("iam:ListUsers", "Users"):
        name = str(user.get("UserName"))
        keys = ctx.collect("iam:ListAccessKeys", "AccessKeyMetadata", UserName=name)
        tags: dict[str, str] | None = None
        for key in keys:
            ctx.looked_at()
            if key.get("Status") != "Active":
                continue
            key_id = str(key.get("AccessKeyId"))
            age = ctx.days_since(key.get("CreateDate"))
            used = ctx.call("iam:GetAccessKeyLastUsed", AccessKeyId=key_id)
            last = (used.get("AccessKeyLastUsed") or {}).get("LastUsedDate")
            idle = ctx.days_since(last)

            judgement = _judge_key(age, idle)
            if judgement is None:
                continue
            if tags is None:
                tags = user_tags(ctx, name)
            if ignored(tags):
                break
            title, severity, recommendation = judgement

            evidence = [f"Active access key belonging to IAM user {name}."]
            if age is not None:
                evidence.append(f"Created {age:,.0f} days ago.")
            if idle is None:
                evidence.append("Has never been used.")
            else:
                service = (used.get("AccessKeyLastUsed") or {}).get("ServiceName")
                where = f", calling {service}" if service and service != "N/A" else ""
                evidence.append(f"Last used {idle:,.0f} days ago{where}.")

            yield Finding(
                check="stale-access-keys",
                module=MODULE,
                title=title,
                resource=Resource(
                    id=key_id,
                    kind="iam:access-key",
                    region=GLOBAL,
                    name=name,
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=recommendation,
                confidence=Confidence.HIGH,
                severity=severity,
            )


def _judge_key(age: float | None, idle: float | None) -> tuple[str, Severity, str] | None:
    """What, if anything, is wrong with one active key."""
    deactivate = (
        "Deactivate it, wait a week for anything to complain, then delete it. "
        "If something still needs AWS access, give it a role instead of a key."
    )
    if idle is None:
        if age is None or age < NEW_KEY_DAYS:
            return None
        severity = Severity.HIGH if age >= LONG_UNUSED_KEY_DAYS else Severity.MEDIUM
        return "Access key never used", severity, deactivate
    if idle >= UNUSED_KEY_DAYS:
        severity = Severity.HIGH if idle >= LONG_UNUSED_KEY_DAYS else Severity.MEDIUM
        return f"Access key unused for {idle:,.0f} days", severity, deactivate
    if age is not None and age >= ROTATE_AFTER_DAYS:
        return (
            f"Access key not rotated in {age:,.0f} days",
            Severity.LOW,
            "Create a second key, move whatever uses this one over, then delete it - "
            "or replace the key with a role, which rotates itself.",
        )
    return None


STALE_ACCESS_KEYS = Check(
    key="stale-access-keys",
    title="Stale access keys",
    looks_for="Active access keys nobody has used in months, or used for a year unrotated.",
    actions=(
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListUserTags",
    ),
    run=stale_access_keys,
)
