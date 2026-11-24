"""Who can get into the account: the root user, console users, access keys."""

from __future__ import annotations

from botocore.exceptions import ClientError
from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.security.identity import (
    CONSOLE_USERS_WITHOUT_MFA,
    MIN_USER_AGE_DAYS,
    ROOT_USER_UNGUARDED,
)

ACCOUNT = "123456789012"


def no_such(operation, code="NoSuchEntity"):
    return ClientError({"Error": {"Code": code, "Message": "none"}}, operation)


def user(name="dana", age=400, signed_in=3):
    data = {
        "UserName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": days_ago(age),
    }
    if signed_in is not None:
        data["PasswordLastUsed"] = days_ago(signed_in)
    return data


# --- the root user ---------------------------------------------------------


def summary(mfa=1, keys=0):
    return {
        "get_account_summary": {
            "SummaryMap": {"AccountMFAEnabled": mfa, "AccountAccessKeysPresent": keys, "Users": 4}
        }
    }


def test_a_root_user_with_mfa_and_no_keys_is_fine():
    outcome = run(ROOT_USER_UNGUARDED, summary())
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_root_user_without_mfa():
    found = findings(ROOT_USER_UNGUARDED, summary(mfa=0))
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Root user without MFA"
    assert finding.resource.region == "global"
    assert finding.resource.arn == "arn:aws:iam::123456789012:root"
    assert finding.level is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.estimate is None


def test_flags_root_access_keys():
    found = findings(ROOT_USER_UNGUARDED, summary(keys=1))
    assert found[0].title == "Root user with access keys"
    assert "delete the root access keys" in found[0].recommendation


def test_both_problems_are_one_finding():
    found = findings(ROOT_USER_UNGUARDED, summary(mfa=0, keys=1))
    assert len(found) == 1
    assert found[0].title == "Root user with access keys and no MFA"
    assert len(found[0].evidence) == 2


def test_an_empty_summary_says_nothing():
    assert findings(ROOT_USER_UNGUARDED, {"get_account_summary": {}}) == ()


def test_missing_permission_skips_the_root_check():
    outcome = run(ROOT_USER_UNGUARDED, {"get_account_summary": denied("GetAccountSummary")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "iam:GetAccountSummary"


# --- console users without MFA ---------------------------------------------


def iam(users, password=True, mfa=(), user_tags=None, **more):
    return {
        "list_users": {"Users": list(users)},
        "get_login_profile": ({"LoginProfile": {}} if password else no_such("GetLoginProfile")),
        "list_mfa_devices": {"MFADevices": list(mfa)},
        "list_user_tags": {"Tags": user_tags or []},
        **more,
    }


def test_flags_a_console_user_signing_in_without_mfa():
    found = findings(CONSOLE_USERS_WITHOUT_MFA, iam([user()]))
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Console user without MFA"
    assert finding.resource.id == "dana"
    assert finding.resource.kind == "iam:user"
    assert finding.level is Severity.HIGH
    assert any("3 days ago" in line for line in finding.evidence)


def test_a_user_with_mfa_is_fine():
    device = {"SerialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/dana"}
    assert findings(CONSOLE_USERS_WITHOUT_MFA, iam([user()], mfa=[device])) == ()


def test_a_user_with_no_password_is_not_a_console_user():
    """`NoSuchEntity` from GetLoginProfile is an answer, not a failure."""
    outcome = run(CONSOLE_USERS_WITHOUT_MFA, iam([user()], password=False))
    assert outcome.status == "ran"
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_a_password_nobody_uses_is_flagged_more_gently():
    found = findings(CONSOLE_USERS_WITHOUT_MFA, iam([user(signed_in=None)]))
    assert found[0].title == "Unused console password, no MFA"
    assert found[0].level is Severity.MEDIUM
    assert "delete the login profile" in found[0].recommendation


def test_a_long_dormant_password_is_not_an_active_user():
    found = findings(CONSOLE_USERS_WITHOUT_MFA, iam([user(signed_in=200)]))
    assert found[0].level is Severity.MEDIUM


def test_a_brand_new_user_gets_a_week_to_set_up_mfa():
    fresh = user(age=MIN_USER_AGE_DAYS - 1, signed_in=None)
    assert findings(CONSOLE_USERS_WITHOUT_MFA, iam([fresh])) == ()


def test_a_new_user_already_signing_in_without_mfa_is_not_excused():
    fresh = user(age=2, signed_in=1)
    assert len(findings(CONSOLE_USERS_WITHOUT_MFA, iam([fresh]))) == 1


def test_respects_the_ignore_tag_on_a_user():
    ignored = iam([user()], user_tags=tags(**{"preflight:ignore": "break-glass"}))
    assert findings(CONSOLE_USERS_WITHOUT_MFA, ignored) == ()


def test_unreadable_user_tags_cost_the_tags_not_the_finding():
    outcome = run(
        CONSOLE_USERS_WITHOUT_MFA,
        iam([user()], list_user_tags=denied("ListUserTags")),
    )
    assert outcome.status == "ran"
    assert len(outcome.findings) == 1


def test_missing_list_users_skips_the_check():
    outcome = run(CONSOLE_USERS_WITHOUT_MFA, {"list_users": denied("ListUsers")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "iam:ListUsers"
