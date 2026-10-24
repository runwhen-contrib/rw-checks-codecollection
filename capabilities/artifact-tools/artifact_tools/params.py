"""Input validation shared by the tasks.

Agents send numbers and booleans both as JSON values and as strings, so both
spellings are accepted. A value out of range is rejected, never clamped: a
silently different `maxMatches` would make a truncated result look complete.
"""

from __future__ import annotations

import re
from typing import Any

_DECIMAL = re.compile(r"[+-]?[0-9]+")


def as_text(name: str, value: Any, *, allow_blank: bool = False) -> str:
    """A required string input. Blank (only whitespace) is refused unless `allow_blank`, as for
    a regular expression, where a single space is a pattern; the empty string never is."""
    if not isinstance(value, str) or not value or (not allow_blank and not value.strip()):
        raise ValueError(f"{name} must be a non-empty string")
    return value


def as_int(name: str, value: Any, *, minimum: int, maximum: int, default: int | None = None) -> int:
    """An integer input in [minimum, maximum]; `None` means "not given" and yields `default`."""
    if value is None:
        if default is None:
            raise ValueError(f"{name} is required")
        return default
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise ValueError(
            f"{name} must be an integer between {minimum} and {maximum}, got {value!r}"
        )
    if isinstance(value, str):
        text = value.strip()
        if not _DECIMAL.fullmatch(text):
            raise ValueError(
                f"{name} must be an integer between {minimum} and {maximum}, got {value!r}"
            )
        value = int(text)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def as_bool(name: str, value: Any, *, default: bool | None = False) -> bool | None:
    """A boolean input: a JSON boolean or the string "true"/"false"; `None` yields `default`."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ValueError(f"{name} must be true or false, got {value!r}")


def as_choice(name: str, value: Any, choices: tuple[str, ...], *, default: str) -> str:
    """One of `choices` (matched case-insensitively); `None` yields `default`."""
    if value is None:
        return default
    if isinstance(value, str) and value.strip().lower() in choices:
        return value.strip().lower()
    raise ValueError(f"{name} must be one of {', '.join(choices)}, got {value!r}")
