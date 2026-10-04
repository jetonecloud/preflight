"""The generated CloudFormation template is the thing users deploy.

These tests parse it rather than string-matching it, so a template that looks
fine but doesn't load stops the build.
"""

import pytest
import yaml

from preflight import __version__
from preflight.core.cfn import (
    POLICY_NAME,
    ROLE_NAME,
    regenerate_command,
    render_role_template,
)
from preflight.core.iam import WriteActionError, collect_actions
from preflight.modules import by_key
from preflight.modules.base import Module, ModuleStatus


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation's `!Ref`-style short tags."""


def _keep_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node, deep=True)}
    return {tag_suffix: loader.construct_mapping(node, deep=True)}


CfnLoader.add_multi_constructor("!", _keep_tag)


@pytest.fixture
def cost():
    return by_key("cost")


@pytest.fixture
def template(cost):
    return render_role_template([cost])


@pytest.fixture
def parsed(template):
    return yaml.load(template, Loader=CfnLoader)


def test_template_is_valid_yaml(parsed):
    assert parsed["AWSTemplateFormatVersion"] == "2010-09-09"
    assert set(parsed) == {
        "AWSTemplateFormatVersion",
        "Description",
        "Parameters",
        "Conditions",
        "Resources",
        "Outputs",
    }


def test_template_creates_a_policy_and_a_role(parsed):
    resources = parsed["Resources"]
    assert resources["PreflightReadOnlyPolicy"]["Type"] == "AWS::IAM::ManagedPolicy"
    assert resources["PreflightReadOnlyRole"]["Type"] == "AWS::IAM::Role"
    assert resources["PreflightReadOnlyPolicy"]["Properties"]["ManagedPolicyName"] == POLICY_NAME
    assert resources["PreflightReadOnlyRole"]["Properties"]["RoleName"] == ROLE_NAME


def _statements(parsed):
    policy = parsed["Resources"]["PreflightReadOnlyPolicy"]["Properties"]["PolicyDocument"]
    return policy["Statement"]


def test_policy_grants_exactly_the_selected_actions(parsed, cost):
    (statement,) = _statements(parsed)
    assert statement["Effect"] == "Allow"
    assert tuple(statement["Action"]) == collect_actions([cost])


def test_policy_grants_nothing_that_can_write(parsed):
    for statement in _statements(parsed):
        assert statement["Effect"] == "Allow", "a Deny would be a different template shape"
        for action in statement["Action"]:
            assert "*" not in action
            verb = action.split(":", 1)[1]
            assert verb.startswith(("Get", "List", "Describe")) or action == (
                "cloudtrail:LookupEvents"
            )


def test_fewer_modules_means_fewer_permissions(cost):
    everything = yaml.load(render_role_template([cost]), Loader=CfnLoader)
    only_base = len(_statements(everything)[0]["Action"])
    assert only_base == len(collect_actions([cost]))
    assert only_base < 52, "selecting one module should not grant the whole policy"


def test_trust_policy_requires_an_external_id_when_one_is_given(parsed):
    role = parsed["Resources"]["PreflightReadOnlyRole"]["Properties"]
    (statement,) = role["AssumeRolePolicyDocument"]["Statement"]
    assert statement["Action"] == "sts:AssumeRole"
    assert statement["Principal"]["AWS"] == {"Ref": "TrustedPrincipalArn"}
    condition = statement["Condition"]["If"]
    assert condition[0] == "HasExternalId"
    assert condition[1]["StringEquals"]["sts:ExternalId"] == {"Ref": "ExternalId"}


def test_external_id_is_not_echoed(parsed):
    assert parsed["Parameters"]["ExternalId"]["NoEcho"] is True


def test_template_outputs_the_role_arn(parsed):
    assert parsed["Outputs"]["RoleArn"]["Value"] == {"GetAtt": "PreflightReadOnlyRole.Arn"}


def test_header_records_how_to_regenerate_it(template, cost):
    header = template.split("AWSTemplateFormatVersion")[0]
    assert f"Preflight {__version__}" in header
    assert regenerate_command([cost]) in header
    assert cost.name in header


def test_module_names_appear_in_the_description(parsed, cost):
    assert cost.name in parsed["Description"]


def test_rendering_is_deterministic(cost):
    assert render_role_template([cost]) == render_role_template([cost])


def test_narrowing_to_services_shrinks_the_policy(cost):
    narrowed = yaml.load(render_role_template([cost], services=["ec2"]), Loader=CfnLoader)
    granted = _statements(narrowed)[0]["Action"]
    assert granted == list(collect_actions([cost], ["ec2"]))
    assert len(granted) < len(collect_actions([cost]))


def test_a_narrowed_header_says_so_and_counts_what_was_granted(cost):
    template = render_role_template([cost], services=["ec2", "rds"])
    header = template.split("AWSTemplateFormatVersion")[0]
    assert "Narrowed at generation time" in header
    assert "ec2, rds" in header
    assert regenerate_command([cost], ["ec2", "rds"]) in header
    assert f"({cost.key}), 9 actions" in header, "7 ec2 + 2 rds, not all 17"


def test_narrowing_is_deterministic(cost):
    assert render_role_template([cost], services=["ec2"]) == render_role_template(
        [cost], services=["ec2"]
    )


def test_rendering_needs_at_least_one_service(cost):
    with pytest.raises(ValueError):
        render_role_template([cost], services=[])


def test_rendering_needs_at_least_one_module():
    with pytest.raises(ValueError):
        render_role_template([])


def test_rendering_refuses_a_module_that_declares_a_write():
    rogue = Module(
        key="rogue",
        name="Rogue",
        summary="declares something it shouldn't",
        status=ModuleStatus.AVAILABLE,
        iam_actions=("iam:DeleteUser",),
    )
    with pytest.raises(WriteActionError):
        render_role_template([rogue])
