"""Builds the CloudFormation role template from the selected modules.

The only input is the module registry — no AWS calls, no credentials, no
network. The output is deterministic: the same modules always produce the same
bytes, so a user who regenerates the template after upgrading Preflight gets a
readable diff instead of a reshuffled file.
"""

from __future__ import annotations

from collections.abc import Sequence
from importlib import resources

from jinja2 import Environment, StrictUndefined

from preflight import __version__
from preflight.core.iam import collect_actions
from preflight.modules import BASE_ACTIONS, Module

TEMPLATE_NAME = "role.cfn.yaml.j2"
DEFAULT_FILENAME = "preflight-role.cfn.yaml"
POLICY_NAME = "PreflightReadOnlyPolicy"
ROLE_NAME = "PreflightReadOnlyRole"


def regenerate_command(modules: Sequence[Module], services: Sequence[str] | None = None) -> str:
    """The command that reproduces a template, recorded in its header."""
    keys = ",".join(module.key for module in modules)
    narrowed = f" --services {','.join(services)}" if services else ""
    return f"preflight scan --modules {keys}{narrowed} --save"


def _load_template() -> str:
    return (
        resources.files("preflight")
        .joinpath("templates", TEMPLATE_NAME)
        .read_text(encoding="utf-8")
    )


def render_role_template(
    modules: Sequence[Module],
    *,
    services: Sequence[str] | None = None,
    version: str = __version__,
) -> str:
    """Render the read-only CloudFormation role template for `modules`.

    `services` narrows the role to a subset of the services the modules
    declare — what the permission picker produces when the user turns some of
    them off. Raises `ValueError` if no modules were given or if the narrowing
    leaves nothing to grant, and `preflight.core.iam.WriteActionError` if any
    declared action isn't provably read-only.
    """
    if not modules:
        raise ValueError("at least one module is required to generate a role")

    actions = collect_actions(modules, services)
    if set(actions) <= set(BASE_ACTIONS):
        raise ValueError("at least one service is required to generate a role")

    env = Environment(
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        autoescape=False,  # YAML output, not HTML
    )
    template = env.from_string(_load_template())
    return template.render(
        version=version,
        modules=tuple(_module_rows(modules, actions)),
        module_names=", ".join(module.name for module in modules),
        actions=actions,
        base_actions=BASE_ACTIONS,
        selected_services=tuple(services) if services else (),
        policy_name=POLICY_NAME,
        role_name=ROLE_NAME,
        regenerate_command=regenerate_command(modules, services),
    )


def _module_rows(modules: Sequence[Module], actions: Sequence[str]) -> list[dict[str, object]]:
    """One header row per module, counting only the actions that made the cut.

    The count has to come from the rendered action list rather than the module
    declaration: with a narrowed service selection they aren't the same number.
    """
    granted = set(actions)
    return [
        {
            "name": module.name,
            "key": module.key,
            "count": len(granted.intersection(module.iam_actions)),
        }
        for module in modules
    ]
