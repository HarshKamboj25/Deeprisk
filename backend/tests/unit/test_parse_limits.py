"""Limit tests for the lockfile parser (Checkpoint D).

``ParseLimits``, ``DEFAULT_PARSE_LIMITS`` and the ``limits`` argument are the new API planned
for Checkpoint D. They are reached through the module object so that each test fails on its
own today (AttributeError) instead of the whole file failing at import. The deep-nesting tests
use only the existing API and currently fail with a raw RecursionError.
"""

import json
from typing import Any

import pytest

from deprisk.core import lockfile as lockfile_module
from deprisk.core.lockfile import LockfileParseError, parse_lockfile, parse_lockfile_text

# json.loads gives up somewhere between 5,000 and 10,000 nested levels on CPython 3.12.3, and
# the exact depth varies by build. Use a depth far beyond any of them.
DEEP_NESTING = 200_000


def limits(**overrides: int) -> Any:
    return lockfile_module.ParseLimits(**overrides)


def lockfile(packages: dict[str, Any], root: Any = None) -> str:
    entries: dict[str, Any] = {"": {} if root is None else root}
    entries.update(packages)
    return json.dumps({"lockfileVersion": 3, "packages": entries})


def pkg(version: str = "1.0.0", **extra: Any) -> dict[str, Any]:
    return {"version": version, **extra}


def n_packages(count: int) -> dict[str, Any]:
    return {f"node_modules/p{i}": pkg() for i in range(count)}


def nested_path(levels: int) -> str:
    return "/".join(f"node_modules/p{i}" for i in range(levels))


# --- the limits object -------------------------------------------------------------------


def test_default_limits_are_pinned() -> None:
    defaults = lockfile_module.DEFAULT_PARSE_LIMITS

    assert defaults == limits()
    assert defaults.max_characters == 50_000_000
    assert defaults.max_packages == 100_000
    assert defaults.max_path_segments == 32
    assert defaults.max_path_length == 1024


def test_overriding_one_limit_keeps_the_other_defaults() -> None:
    defaults = lockfile_module.DEFAULT_PARSE_LIMITS
    custom = limits(max_packages=5)

    assert custom.max_packages == 5
    assert custom.max_characters == defaults.max_characters
    assert custom.max_path_segments == defaults.max_path_segments
    assert custom.max_path_length == defaults.max_path_length


@pytest.mark.parametrize("value", [0, -1])
@pytest.mark.parametrize(
    "field",
    ["max_characters", "max_packages", "max_path_segments", "max_path_length"],
)
def test_non_positive_limit_is_rejected(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        limits(**{field: value})


def test_limits_are_immutable() -> None:
    custom = limits()

    # A frozen dataclass raises AttributeError; a frozen pydantic model raises ValueError.
    with pytest.raises((AttributeError, ValueError)):
        custom.max_packages = 1


# --- character limit -----------------------------------------------------------------------


def test_content_at_the_character_limit_is_accepted() -> None:
    text = lockfile(n_packages(2))

    parsed = parse_lockfile(text, limits=limits(max_characters=len(text)))

    assert len(parsed.nodes) == 2


def test_content_over_the_character_limit_is_rejected() -> None:
    text = lockfile(n_packages(2))

    with pytest.raises(LockfileParseError, match="character limit"):
        parse_lockfile(text, limits=limits(max_characters=len(text) - 1))


def test_size_is_checked_before_parsing() -> None:
    """Oversized input is refused on its length alone, even when it is not valid JSON."""
    with pytest.raises(LockfileParseError, match="character limit"):
        parse_lockfile("x" * 101, limits=limits(max_characters=100))


# --- package count limit ---------------------------------------------------------------------


def test_package_count_at_the_limit_is_accepted() -> None:
    """The root entry is not an installed package and does not count."""
    parsed = parse_lockfile(lockfile(n_packages(3)), limits=limits(max_packages=3))

    assert len(parsed.nodes) == 3


def test_package_count_over_the_limit_is_rejected() -> None:
    with pytest.raises(LockfileParseError, match="package limit"):
        parse_lockfile(lockfile(n_packages(4)), limits=limits(max_packages=3))


# --- install path depth and length ----------------------------------------------------------


def test_path_depth_at_the_limit_is_accepted() -> None:
    path = nested_path(4)

    parsed = parse_lockfile(lockfile({path: pkg()}), limits=limits(max_path_segments=4))

    assert [node.install_path for node in parsed.nodes] == [path]


def test_path_depth_over_the_limit_is_rejected() -> None:
    with pytest.raises(LockfileParseError, match="path depth limit"):
        parse_lockfile(lockfile({nested_path(5): pkg()}), limits=limits(max_path_segments=4))


def test_scoped_packages_count_as_one_level() -> None:
    path = "node_modules/@s/a/node_modules/@s/b"

    parsed = parse_lockfile(lockfile({path: pkg()}), limits=limits(max_path_segments=2))
    assert len(parsed.nodes) == 1

    with pytest.raises(LockfileParseError, match="path depth limit"):
        parse_lockfile(lockfile({path: pkg()}), limits=limits(max_path_segments=1))


def test_path_length_at_the_limit_is_accepted() -> None:
    path = "node_modules/" + "a" * 50

    parsed = parse_lockfile(lockfile({path: pkg()}), limits=limits(max_path_length=len(path)))

    assert [node.install_path for node in parsed.nodes] == [path]


def test_path_length_over_the_limit_is_rejected() -> None:
    path = "node_modules/" + "a" * 50

    with pytest.raises(LockfileParseError, match="path length limit"):
        parse_lockfile(lockfile({path: pkg()}), limits=limits(max_path_length=len(path) - 1))


# --- the text wrapper and the defaults ---------------------------------------------------------


def test_parse_lockfile_text_accepts_limits() -> None:
    text = lockfile(n_packages(2))

    with pytest.raises(LockfileParseError, match="package limit"):
        parse_lockfile_text(text, limits=limits(max_packages=1))


def test_default_limits_accept_ordinary_input() -> None:
    packages = n_packages(1_000)
    packages[nested_path(4)] = pkg()

    assert len(parse_lockfile(lockfile(packages)).nodes) == 1_001
    assert len(parse_lockfile_text(lockfile(n_packages(2)))) == 2


# --- deeply nested JSON ----------------------------------------------------------------------


def test_deeply_nested_array_raises_a_typed_error() -> None:
    """Currently escapes as a raw RecursionError, which an API caller would see as a crash."""
    with pytest.raises(LockfileParseError, match="nested too deeply"):
        parse_lockfile("[" * DEEP_NESTING + "]" * DEEP_NESTING)


def test_deeply_nested_objects_raise_a_typed_error() -> None:
    with pytest.raises(LockfileParseError, match="nested too deeply"):
        parse_lockfile('{"a":' * DEEP_NESTING + "1" + "}" * DEEP_NESTING)


def test_deeply_nested_value_inside_a_lockfile_raises_a_typed_error() -> None:
    text = (
        '{"lockfileVersion":3,"packages":{"":{}},"extra":'
        + "[" * DEEP_NESTING
        + "]" * DEEP_NESTING
        + "}"
    )

    with pytest.raises(LockfileParseError, match="nested too deeply"):
        parse_lockfile(text)


def test_moderate_nesting_inside_a_lockfile_is_accepted() -> None:
    text = '{"lockfileVersion":3,"packages":{"":{}},"extra":' + "[" * 50 + "]" * 50 + "}"

    assert parse_lockfile(text).nodes == ()
