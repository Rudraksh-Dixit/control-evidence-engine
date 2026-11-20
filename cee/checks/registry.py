from __future__ import annotations

from typing import Iterable

from cee.checks.base import Check

_REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} is missing a check id")
    if cls.id in _REGISTRY:
        raise ValueError(f"Duplicate check id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def build_checks(check_ids: Iterable[str] | None = None) -> list[Check]:
    selected = list(check_ids) if check_ids is not None else list(_REGISTRY)
    missing = [check_id for check_id in selected if check_id not in _REGISTRY]
    if missing:
        raise KeyError(f"Unknown checks: {', '.join(sorted(missing))}")
    return [_REGISTRY[check_id]() for check_id in selected]


def registered_ids() -> list[str]:
    return list(_REGISTRY)
