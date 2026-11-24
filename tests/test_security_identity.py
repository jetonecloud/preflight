"""Who can get into the account: the root user, console users, access keys."""

from __future__ import annotations

from conftest import denied, findings, run

from preflight.core.findings import Confidence, Severity
from preflight.modules.security.identity import ROOT_USER_UNGUARDED

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
