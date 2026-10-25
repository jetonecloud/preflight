"""The shape of a Preflight module.

A module is a group of related checks plus the IAM actions those checks need.
Nothing here touches AWS: a module declares its permissions so Preflight can
build the smallest possible read-only role before any scan happens.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    from preflight.core.findings import Finding
    from preflight.core.scan import ScanContext

# Actions every scan needs, whatever modules are selected. Preflight calls
# GetCallerIdentity first so it can show you which account it's about to read
# and warn you if the identity has more access than it needs.
BASE_ACTIONS: tuple[str, ...] = ("sts:GetCallerIdentity",)


class ModuleStatus(Enum):
    """Whether a module can run yet."""

    AVAILABLE = "available"
    COMING_SOON = "coming-soon"

    @property
    def label(self) -> str:
        return "available" if self is ModuleStatus.AVAILABLE else "coming soon"


@dataclass(frozen=True)
class Check:
    """One question a module asks about an account.

    A check owns its permissions as well as its logic. `actions` is not
    documentation: the scan runner only lets a check make the calls listed
    here, so a check that reaches for something it didn't declare fails
    immediately in development instead of working on a wide-open profile and
    breaking on a Preflight role — or, worse, reading something the user
    never agreed to hand over.
    """

    key: str
    title: str
    #: One line, in plain words, shown before the scan starts and in the
    #: report. This is the promise the check is making to the reader.
    looks_for: str
    actions: tuple[str, ...]
    run: Callable[[ScanContext], Iterable[Finding]]

    def __post_init__(self) -> None:
        if not self.actions:
            raise ValueError(f"check '{self.key}' declares no actions")


@dataclass(frozen=True)
class Module:
    """A named group of checks and the read-only IAM actions they need.

    Modules are declared, not discovered: adding one means adding a `Module`
    to the registry with every action its checks call. The actions are the
    contract — `preflight scan` builds the IAM role from them, so a check that
    calls something it didn't declare will fail against a Preflight role
    rather than quietly reading more than the user agreed to.
    """

    key: str
    name: str
    summary: str
    iam_actions: tuple[str, ...]
    status: ModuleStatus = ModuleStatus.COMING_SOON
    #: The checks this module runs, in report order. Empty for a module
    #: that's declared its permissions but hasn't shipped its logic yet.
    checks: tuple[Check, ...] = ()
    #: Actions the module needs that no single check owns — region discovery,
    #: price lookups, the spend figure the report is measured against. Kept
    #: separate so `iam_actions` can be checked against the checks that use it.
    support_actions: tuple[str, ...] = ()

    @property
    def is_available(self) -> bool:
        return self.status is ModuleStatus.AVAILABLE

    @property
    def check_actions(self) -> tuple[str, ...]:
        """Every action the module's checks declare, deduplicated and sorted."""
        actions: set[str] = set()
        for check in self.checks:
            actions.update(check.actions)
        return tuple(sorted(actions))

    def check(self, key: str) -> Check | None:
        for check in self.checks:
            if check.key == key:
                return check
        return None


class ModuleError(Exception):
    """Base class for problems with a module selection."""


class UnknownModuleError(ModuleError):
    """A requested module key isn't in the registry."""

    def __init__(self, keys: tuple[str, ...]) -> None:
        self.keys = keys
        super().__init__(f"unknown module(s): {', '.join(keys)}")


class ModuleNotAvailableError(ModuleError):
    """A requested module exists but hasn't shipped yet."""

    def __init__(self, keys: tuple[str, ...]) -> None:
        self.keys = keys
        super().__init__(f"module(s) not available yet: {', '.join(keys)}")
