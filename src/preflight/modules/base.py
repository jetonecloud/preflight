"""The shape of a Preflight module.

A module is a group of related checks plus the IAM actions those checks need.
Nothing here touches AWS: a module declares its permissions so Preflight can
build the smallest possible read-only role before any scan happens.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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

    @property
    def is_available(self) -> bool:
        return self.status is ModuleStatus.AVAILABLE


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
