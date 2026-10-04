"""The module registry.

`REGISTRY` is the list `preflight scan` shows and the single source of truth
for which IAM actions end up in a generated role.
"""

from __future__ import annotations

from collections.abc import Iterable

from preflight.modules.base import (
    BASE_ACTIONS,
    Module,
    ModuleError,
    ModuleNotAvailableError,
    ModuleStatus,
    UnknownModuleError,
)
from preflight.modules.cost import COST
from preflight.modules.planned import (
    BUS_FACTOR,
    DELIVERY,
    OBSERVABILITY,
    RELIABILITY,
    SECURITY,
)

# Display order for the picker: available modules first, then the rest in the
# order we expect to ship them.
REGISTRY: tuple[Module, ...] = (
    COST,
    SECURITY,
    RELIABILITY,
    DELIVERY,
    OBSERVABILITY,
    BUS_FACTOR,
)

__all__ = [
    "BASE_ACTIONS",
    "REGISTRY",
    "Module",
    "ModuleError",
    "ModuleNotAvailableError",
    "ModuleStatus",
    "UnknownModuleError",
    "available_modules",
    "by_key",
    "resolve",
]


def available_modules() -> tuple[Module, ...]:
    """Modules that can run today."""
    return tuple(module for module in REGISTRY if module.is_available)


def by_key(key: str) -> Module | None:
    """Look a module up by key, case- and whitespace-insensitively."""
    wanted = key.strip().lower()
    for module in REGISTRY:
        if module.key == wanted:
            return module
    return None


def resolve(keys: Iterable[str]) -> tuple[Module, ...]:
    """Turn module keys into modules, in registry order.

    `all` expands to every available module. Raises `UnknownModuleError` for
    keys that don't exist and `ModuleNotAvailableError` for ones that haven't
    shipped, so the caller can tell the user which of the two happened.
    """
    wanted: list[str] = []
    for key in keys:
        cleaned = key.strip().lower()
        if not cleaned:
            continue
        if cleaned == "all":
            wanted.extend(module.key for module in available_modules())
        else:
            wanted.append(cleaned)

    unknown = tuple(dict.fromkeys(key for key in wanted if by_key(key) is None))
    if unknown:
        raise UnknownModuleError(unknown)

    not_ready = tuple(
        dict.fromkeys(key for key in wanted if not by_key(key).is_available)  # type: ignore[union-attr]
    )
    if not_ready:
        raise ModuleNotAvailableError(not_ready)

    selected = set(wanted)
    return tuple(module for module in REGISTRY if module.key in selected)
