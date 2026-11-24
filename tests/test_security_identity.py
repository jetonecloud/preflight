"""Who can get into the account: the root user, console users, access keys."""

from __future__ import annotations

from botocore.exceptions import ClientError
from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.security.identity import (
    CONSOLE_USERS_WITHOUT_MFA,
    MIN_USER_AGE_DAYS,
    ROOT_USER_UNGUARDED,
    STALE_ACCESS_KEYS,
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


# --- access keys -----------------------------------------------------------

KEY = "AKIAEXAMPLEKEY000001"


def keyring(age=400, last_used=2, status="Active", service="s3", user_tags=None, **more):
    used = {"Region": "us-east-1", "ServiceName": service}
    if last_used is not None:
        used["LastUsedDate"] = days_ago(last_used)
    return {
        "list_users": {"Users": [user("deploy-bot", signed_in=None)]},
        "list_access_keys": {
            "AccessKeyMetadata": [
                {"AccessKeyId": KEY, "Status": status, "CreateDate": days_ago(age)}
            ]
        },
        "get_access_key_last_used": {"UserName": "deploy-bot", "AccessKeyLastUsed": used},
        "list_user_tags": {"Tags": user_tags or []},
        **more,
    }


def test_a_key_in_use_and_recently_made_is_fine():
    outcome = run(STALE_ACCESS_KEYS, keyring(age=100, last_used=1))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_key_nobody_has_used_in_months():
    found = findings(STALE_ACCESS_KEYS, keyring(last_used=120))
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Access key unused for 120 days"
    assert finding.resource.id == KEY
    assert finding.resource.name == "deploy-bot"
    assert finding.level is Severity.MEDIUM
    assert any("calling s3" in line for line in finding.evidence)


def test_a_key_unused_for_a_year_is_high_severity():
    found = findings(STALE_ACCESS_KEYS, keyring(age=800, last_used=400))
    assert found[0].level is Severity.HIGH


def test_flags_a_key_that_was_never_used():
    found = findings(STALE_ACCESS_KEYS, keyring(age=60, last_used=None, service="N/A"))
    assert found[0].title == "Access key never used"
    assert any("never been used" in line for line in found[0].evidence)


def test_a_new_unused_key_is_probably_on_its_way_somewhere():
    assert findings(STALE_ACCESS_KEYS, keyring(age=5, last_used=None)) == ()


def test_an_old_key_in_daily_use_should_be_rotated():
    found = findings(STALE_ACCESS_KEYS, keyring(age=500, last_used=1))
    assert found[0].title == "Access key not rotated in 500 days"
    assert found[0].level is Severity.LOW


def test_an_inactive_key_is_already_dealt_with():
    assert findings(STALE_ACCESS_KEYS, keyring(last_used=400, status="Inactive")) == ()


def test_respects_the_ignore_tag_on_the_keys_user():
    ignored = keyring(last_used=400, user_tags=tags(**{"preflight:ignore": "true"}))
    assert findings(STALE_ACCESS_KEYS, ignored) == ()


def test_missing_last_used_permission_skips_and_names_it():
    outcome = run(
        STALE_ACCESS_KEYS,
        keyring(get_access_key_last_used=denied("GetAccessKeyLastUsed")),
    )
    assert outcome.status == "skipped"
    assert outcome.missing_action == "iam:GetAccessKeyLastUsed"
