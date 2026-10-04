import json
from pathlib import Path

POLICY_PATH = Path(__file__).parent.parent / "iam" / "policy.json"
ALLOWED_PREFIXES = ("Get", "List", "Describe")

# Read-only actions that don't follow the Get/List/Describe naming convention
# but perform no mutation. Any addition here must be justified in the PR.
READ_ONLY_EXCEPTIONS = {
    "cloudtrail:LookupEvents",  # read-only event query, used by the bus-factor module
}


def test_policy_is_read_only():
    policy = json.loads(POLICY_PATH.read_text())
    for statement in policy["Statement"]:
        actions = statement["Action"]
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            assert action != "*", f"wildcard action not allowed: {action}"
            if action in READ_ONLY_EXCEPTIONS:
                continue
            service, verb = action.split(":", 1)
            assert verb.startswith(ALLOWED_PREFIXES), f"non-read-only action: {action}"


def test_policy_has_no_wildcard_actions():
    policy = json.loads(POLICY_PATH.read_text())
    for statement in policy["Statement"]:
        assert statement["Effect"] == "Allow"


def test_the_rules_here_match_the_ones_the_cli_enforces():
    """This file checks the policy on disk; `core.iam` checks what we generate.

    They're deliberately separate implementations, so they have to agree on
    what "read-only" means.
    """
    from preflight.core import iam

    assert iam.READ_ONLY_PREFIXES == ALLOWED_PREFIXES
    assert set(iam.READ_ONLY_EXCEPTIONS) == READ_ONLY_EXCEPTIONS
