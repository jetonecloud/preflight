import pytest

from preflight.core.iam import (
    WriteActionError,
    assert_read_only,
    collect_actions,
    group_by_service,
    is_read_only_action,
    selectable_services,
)
from preflight.modules import BASE_ACTIONS, by_key
from preflight.modules.base import Module, ModuleStatus


@pytest.mark.parametrize(
    "action",
    [
        "ec2:DescribeInstances",
        "s3:ListAllMyBuckets",
        "iam:GetAccountSummary",
        "cloudtrail:LookupEvents",  # documented exception
    ],
)
def test_read_only_actions_are_accepted(action):
    assert is_read_only_action(action)


@pytest.mark.parametrize(
    "action",
    [
        "*",
        "s3:*",
        "ec2:Describe*",
        "iam:CreateUser",
        "s3:DeleteObject",
        "ec2:TerminateInstances",
        "sts:AssumeRole",
        "ec2",
        "",
    ],
)
def test_everything_else_is_rejected(action):
    assert not is_read_only_action(action)


def test_assert_read_only_names_every_offender():
    with pytest.raises(WriteActionError) as caught:
        assert_read_only(["ec2:DescribeInstances", "iam:CreateUser", "s3:*"])
    assert caught.value.actions == ("iam:CreateUser", "s3:*")


def test_collect_actions_includes_the_base_actions():
    actions = collect_actions([by_key("cost")])
    assert set(BASE_ACTIONS) <= set(actions)


def test_collect_actions_sorts_and_deduplicates():
    cost = by_key("cost")
    actions = collect_actions([cost, cost])
    assert len(actions) == len(set(actions))
    assert list(actions) == sorted(actions, key=lambda a: (a.split(":", 1)[0], a))


def test_collect_actions_groups_services_together():
    actions = collect_actions([by_key("cost")])
    services = [action.split(":", 1)[0] for action in actions]
    assert services == sorted(services), "a service's actions should be contiguous"


def test_narrowing_to_services_drops_the_rest():
    cost = by_key("cost")
    actions = collect_actions([cost], ["ec2"])
    assert "ec2:DescribeVolumes" in actions
    assert "rds:DescribeDBInstances" not in actions
    assert len(actions) < len(collect_actions([cost]))


def test_narrowing_keeps_the_base_actions_whatever_is_asked_for():
    actions = collect_actions([by_key("cost")], ["ec2"])
    assert set(BASE_ACTIONS) <= set(actions)
    assert collect_actions([by_key("cost")], []) == BASE_ACTIONS


def test_narrowing_is_case_insensitive():
    assert collect_actions([by_key("cost")], ["EC2"]) == collect_actions([by_key("cost")], ["ec2"])


def test_group_by_service_sorts_both_levels():
    groups = group_by_service(["s3:ListAllMyBuckets", "ec2:DescribeVolumes", "ec2:DescribeImages"])
    assert list(groups) == ["ec2", "s3"]
    assert groups["ec2"] == ("ec2:DescribeImages", "ec2:DescribeVolumes")


def test_selectable_services_leaves_out_the_base_actions():
    groups = selectable_services([by_key("cost")])
    assert "sts" not in groups, "every scan needs it, so it isn't optional"
    assert groups["ec2"], "the rest can be switched off"
    assert sum(len(actions) for actions in groups.values()) == len(
        collect_actions([by_key("cost")])
    ) - len(BASE_ACTIONS)


def test_collect_actions_refuses_a_module_that_declares_a_write():
    rogue = Module(
        key="rogue",
        name="Rogue",
        summary="declares something it shouldn't",
        status=ModuleStatus.AVAILABLE,
        iam_actions=("ec2:TerminateInstances",),
    )
    with pytest.raises(WriteActionError):
        collect_actions([rogue])
