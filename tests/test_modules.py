import json
from pathlib import Path

import pytest

from preflight.core.iam import is_read_only_action
from preflight.modules import (
    BASE_ACTIONS,
    REGISTRY,
    ModuleNotAvailableError,
    UnknownModuleError,
    available_modules,
    by_key,
    resolve,
)

POLICY_PATH = Path(__file__).parent.parent / "iam" / "policy.json"


def policy_actions() -> set[str]:
    policy = json.loads(POLICY_PATH.read_text())
    actions: set[str] = set()
    for statement in policy["Statement"]:
        declared = statement["Action"]
        actions.update([declared] if isinstance(declared, str) else declared)
    return actions


def test_registry_keys_are_unique():
    keys = [module.key for module in REGISTRY]
    assert len(keys) == len(set(keys))


def test_registry_keys_are_cli_friendly():
    for module in REGISTRY:
        assert module.key == module.key.lower().strip()
        assert " " not in module.key
        assert module.key != "all", "'all' is reserved by the picker"


def test_every_declared_action_is_read_only():
    for module in REGISTRY:
        for action in module.iam_actions:
            assert is_read_only_action(action), f"{module.key} declares {action}"
    for action in BASE_ACTIONS:
        assert is_read_only_action(action)


def test_modules_declare_no_duplicate_actions():
    for module in REGISTRY:
        assert len(module.iam_actions) == len(set(module.iam_actions)), module.key


def test_registry_matches_the_checked_in_policy():
    """`iam/policy.json` is the role you get with every module selected.

    If this fails, a module gained or lost an action and the checked-in policy
    wasn't regenerated — or vice versa.
    """
    declared = set(BASE_ACTIONS)
    for module in REGISTRY:
        declared.update(module.iam_actions)
    on_disk = policy_actions()
    assert declared - on_disk == set(), "declared by a module but missing from iam/policy.json"
    assert on_disk - declared == set(), "in iam/policy.json but no module claims it"


def test_cost_is_the_only_available_module():
    assert [module.key for module in available_modules()] == ["cost"]


def test_by_key_is_forgiving_about_case_and_space():
    assert by_key("  COST ") is not None
    assert by_key("cost").name == "Cost Check"
    assert by_key("nope") is None


def test_resolve_returns_registry_order():
    assert resolve(["cost"]) == (by_key("cost"),)


def test_resolve_deduplicates():
    assert resolve(["cost", "cost"]) == (by_key("cost"),)


def test_resolve_expands_all_to_available_modules():
    assert resolve(["all"]) == available_modules()


def test_resolve_rejects_unknown_modules():
    with pytest.raises(UnknownModuleError) as caught:
        resolve(["cost", "nope"])
    assert caught.value.keys == ("nope",)


def test_resolve_rejects_modules_that_have_not_shipped():
    with pytest.raises(ModuleNotAvailableError) as caught:
        resolve(["security"])
    assert caught.value.keys == ("security",)


def test_unknown_is_reported_before_not_available():
    """A typo and a coming-soon module together: the typo is the real mistake."""
    with pytest.raises(UnknownModuleError):
        resolve(["security", "nope"])


# --- checks and the actions they declare ----------------------------------


def test_every_available_module_has_checks():
    for module in available_modules():
        assert module.checks, f"{module.key} is marked available but runs nothing"


def test_check_keys_are_unique_within_a_module():
    for module in REGISTRY:
        keys = [check.key for check in module.checks]
        assert len(keys) == len(set(keys))


def test_a_modules_permissions_are_exactly_what_its_checks_use():
    """The role Preflight generates and the calls it makes can't drift.

    `iam_actions` is what ends up in the deployed policy, and this is the
    test that keeps it honest: every action is used by a check or declared
    as module-level support, and nothing a check uses is missing from it.
    """
    for module in available_modules():
        declared = set(module.iam_actions)
        used = set(module.check_actions) | set(module.support_actions)
        assert used - declared == set(), f"{module.key} calls actions it doesn't declare"
        assert declared - used == set(), f"{module.key} asks for actions nothing uses"


def test_every_check_action_is_read_only():
    for module in REGISTRY:
        for check in module.checks:
            for action in check.actions:
                assert is_read_only_action(action), f"{check.key} declares {action}"


def test_checks_describe_themselves_in_plain_words():
    for module in REGISTRY:
        for check in module.checks:
            assert check.title and check.title[0].isupper()
            assert check.looks_for.endswith("."), f"{check.key}: looks_for reads as a sentence"


def test_a_check_must_declare_at_least_one_action():
    from preflight.modules.base import Check

    with pytest.raises(ValueError, match="declares no actions"):
        Check(key="empty", title="Empty", looks_for="nothing.", actions=(), run=lambda ctx: ())
