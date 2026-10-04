"""The read-only invariant.

Preflight's main promise is that it cannot change anything in your account.
This module is where that promise is enforced in code: every action that
reaches a generated IAM policy passes through `assert_read_only` first, so a
mistake in a module declaration fails at generation time instead of ending up
in a role someone deploys.
"""

from __future__ import annotations

from collections.abc import Iterable

from preflight.modules.base import BASE_ACTIONS, Module

#: Action verbs that cannot mutate state.
READ_ONLY_PREFIXES: tuple[str, ...] = ("Get", "List", "Describe")

#: Read-only actions that don't follow the Get/List/Describe naming convention.
#: Keep in sync with tests/test_policy.py and the policy-check CI job. Any
#: addition here must be justified in the pull request that makes it.
READ_ONLY_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "cloudtrail:LookupEvents",  # read-only event query, used by Bus factor
    }
)


class WriteActionError(ValueError):
    """An action that isn't provably read-only reached policy generation."""

    def __init__(self, actions: tuple[str, ...]) -> None:
        self.actions = actions
        super().__init__(
            "refusing to generate a policy containing actions that are not "
            f"read-only: {', '.join(actions)}"
        )


def is_read_only_action(action: str) -> bool:
    """Whether `action` is a specific, non-mutating AWS action.

    Wildcards are never read-only: `*` and `s3:*` would both grant writes.
    """
    if action in READ_ONLY_EXCEPTIONS:
        return True
    if "*" in action or ":" not in action:
        return False
    _service, verb = action.split(":", 1)
    return verb.startswith(READ_ONLY_PREFIXES)


def assert_read_only(actions: Iterable[str]) -> None:
    """Raise `WriteActionError` if any action could change something."""
    offenders = tuple(action for action in actions if not is_read_only_action(action))
    if offenders:
        raise WriteActionError(offenders)


def service_of(action: str) -> str:
    """The AWS service an action belongs to: `ec2` for `ec2:DescribeVolumes`."""
    return action.split(":", 1)[0]


def group_by_service(actions: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Actions bucketed by service, both the buckets and their contents sorted."""
    groups: dict[str, list[str]] = {}
    for action in actions:
        groups.setdefault(service_of(action), []).append(action)
    return {service: tuple(sorted(groups[service])) for service in sorted(groups)}


def selectable_services(modules: Iterable[Module]) -> dict[str, tuple[str, ...]]:
    """The service groups a user is allowed to narrow a role down to.

    `BASE_ACTIONS` are left out: every scan needs them, so they aren't
    something the picker can switch off.
    """
    actions: set[str] = set()
    for module in modules:
        actions.update(module.iam_actions)
    return group_by_service(actions - set(BASE_ACTIONS))


def collect_actions(
    modules: Iterable[Module], services: Iterable[str] | None = None
) -> tuple[str, ...]:
    """The deduplicated, sorted actions needed to run `modules`.

    Always includes `BASE_ACTIONS`. Passing `services` narrows the result to
    those services, which is how the picker in `preflight scan` hands back a
    role smaller than the modules alone would imply. Sorting keeps a
    regenerated template byte-identical to the last one, so the file diffs
    cleanly when a module's permissions change.
    """
    actions = set(BASE_ACTIONS)
    for module in modules:
        actions.update(module.iam_actions)
    if services is not None:
        wanted = {service.strip().lower() for service in services}
        actions = {
            action
            for action in actions
            if action in BASE_ACTIONS or service_of(action).lower() in wanted
        }
    ordered = tuple(sorted(actions, key=lambda action: (service_of(action), action)))
    assert_read_only(ordered)
    return ordered
