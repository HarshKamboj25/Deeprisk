"""Hardening tests: malformed or hostile lockfile input must raise LockfileParseError.

Checkpoint D. Many of these fail against the Checkpoint C parser on purpose: it accepts odd
install paths, odd package names, duplicate JSON keys and a missing root entry.
"""

import json
from typing import Any

import pytest

from deprisk.core.lockfile import LockfileParseError, parse_lockfile


def lockfile(packages: dict[str, Any], root: Any = None) -> str:
    entries: dict[str, Any] = {"": {} if root is None else root}
    entries.update(packages)
    return json.dumps({"lockfileVersion": 3, "packages": entries})


def pkg(version: str = "1.0.0", **extra: Any) -> dict[str, Any]:
    return {"version": version, **extra}


# --- install paths --------------------------------------------------------------------

REJECTED_PATHS = [
    pytest.param("node_modules/foo/lib", id="extra-segment-after-name"),
    pytest.param("node_modules/../x", id="parent-directory"),
    pytest.param("node_modules/./x", id="current-directory"),
    pytest.param("node_modules/a/../b", id="parent-directory-in-the-middle"),
    pytest.param("node_modules/a//b", id="empty-segment"),
    pytest.param("node_modules//x", id="empty-first-segment"),
    pytest.param("node_modules/a\\b", id="backslash"),
    pytest.param("node_modules/a\x00b", id="nul-byte"),
    pytest.param("node_modules/a\nb", id="newline"),
    pytest.param("node_modules/", id="empty-name"),
    pytest.param("node_modules/a/node_modules/", id="trailing-empty-name"),
    pytest.param("node_modules/@scope", id="scope-without-name"),
    pytest.param("node_modules/@scope/", id="scope-with-empty-name"),
    pytest.param("node_modules/@/pkg", id="empty-scope"),
    pytest.param("node_modules/a/node_modules/@scope", id="nested-scope-without-name"),
    pytest.param("packages/app", id="workspace-member-path"),
    pytest.param("packages/app/node_modules/x", id="path-under-workspace-member"),
    pytest.param("/node_modules/x", id="leading-slash"),
]


@pytest.mark.parametrize("install_path", REJECTED_PATHS)
def test_invalid_install_path_is_rejected(install_path: str) -> None:
    with pytest.raises(LockfileParseError):
        parse_lockfile(lockfile({install_path: pkg()}))


ACCEPTED_PATHS = [
    pytest.param("node_modules/lodash", "lodash", id="plain"),
    pytest.param("node_modules/lodash.merge", "lodash.merge", id="dotted"),
    pytest.param("node_modules/a-b_c", "a-b_c", id="hyphen-and-underscore"),
    pytest.param("node_modules/UPPER.Case", "UPPER.Case", id="legacy-uppercase"),
    pytest.param("node_modules/@types/node", "@types/node", id="scoped"),
    pytest.param("node_modules/a/node_modules/b", "b", id="nested"),
    pytest.param("node_modules/a/node_modules/@scope/pkg", "@scope/pkg", id="nested-scoped"),
    pytest.param("node_modules/@s/a/node_modules/b", "b", id="nested-under-scoped-parent"),
    pytest.param("node_modules/a/node_modules/b/node_modules/c", "c", id="three-levels"),
]


@pytest.mark.parametrize(("install_path", "expected_name"), ACCEPTED_PATHS)
def test_valid_install_path_is_accepted(install_path: str, expected_name: str) -> None:
    (node,) = parse_lockfile(lockfile({install_path: pkg()})).nodes

    assert node.install_path == install_path
    assert node.name == expected_name


# --- the entry 'name' field ---------------------------------------------------------------

INVALID_NAMES = [
    pytest.param("", id="empty"),
    pytest.param(".", id="dot"),
    pytest.param("..", id="dot-dot"),
    pytest.param("a/b", id="slash-in-unscoped-name"),
    pytest.param("../../etc", id="path-traversal"),
    pytest.param("x y", id="whitespace"),
    pytest.param("a\x00b", id="nul-byte"),
    pytest.param("a\nb", id="newline"),
    pytest.param("a\\b", id="backslash"),
    pytest.param("@scope", id="scope-without-name"),
    pytest.param("@scope/", id="scope-with-empty-name"),
    pytest.param("@/pkg", id="empty-scope"),
    pytest.param("@scope/pkg/extra", id="too-many-segments"),
]


@pytest.mark.parametrize("name", INVALID_NAMES)
def test_invalid_name_field_is_rejected(name: str) -> None:
    with pytest.raises(LockfileParseError):
        parse_lockfile(lockfile({"node_modules/p": pkg(name=name)}))


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(None, id="null"),
        pytest.param(0, id="zero"),
        pytest.param(False, id="false"),
        pytest.param([], id="empty-list"),
        pytest.param({}, id="empty-object"),
        pytest.param(123, id="number"),
        pytest.param(["x"], id="list"),
        pytest.param(True, id="true"),
    ],
)
def test_non_string_name_field_is_rejected(name: Any) -> None:
    with pytest.raises(LockfileParseError):
        parse_lockfile(lockfile({"node_modules/p": pkg(name=name)}))


@pytest.mark.parametrize("name", ["lodash", "@scope/pkg", "lodash.merge"])
def test_valid_alias_name_is_accepted(name: str) -> None:
    (node,) = parse_lockfile(lockfile({"node_modules/myalias": pkg(name=name)})).nodes

    assert node.name == name
    assert node.install_path == "node_modules/myalias"


# --- duplicate JSON keys -------------------------------------------------------------------

DUPLICATE_KEY_DOCUMENTS = [
    pytest.param(
        '{"lockfileVersion":3,"packages":{"":{},'
        '"node_modules/x":{"version":"1.0.0"},"node_modules/x":{"version":"9.9.9"}}}',
        id="package-path",
    ),
    pytest.param(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"^1","a":"^9"}}}}',
        id="root-dependency",
    ),
    pytest.param(
        '{"lockfileVersion":3,"packages":{"":{},"node_modules/a":'
        '{"version":"1.0.0","dependencies":{"b":"^1","b":"^2"}}}}',
        id="package-dependency",
    ),
    pytest.param(
        '{"lockfileVersion":3,"lockfileVersion":2,"packages":{"":{}}}',
        id="top-level-key",
    ),
    pytest.param(
        '{"lockfileVersion":3,"packages":{"":{},'
        '"node_modules/x":{"version":"1.0.0","version":"2.0.0"}}}',
        id="entry-field",
    ),
    pytest.param(
        '{"lockfileVersion":3,"packages":{"":{},"":{"dependencies":{}}}}',
        id="root-entry",
    ),
]


@pytest.mark.parametrize("document", DUPLICATE_KEY_DOCUMENTS)
def test_duplicate_json_keys_are_rejected(document: str) -> None:
    with pytest.raises(LockfileParseError, match="Duplicate JSON key"):
        parse_lockfile(document)


def test_the_same_key_in_different_objects_is_not_a_duplicate() -> None:
    text = lockfile(
        {
            "node_modules/a": pkg(dependencies={"c": "^1.0.0"}),
            "node_modules/b": pkg(dependencies={"c": "^1.0.0"}),
            "node_modules/c": pkg(),
        },
        root={"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}},
    )

    assert len(parse_lockfile(text).nodes) == 3


# --- root entry ------------------------------------------------------------------------------


def test_missing_root_entry_is_rejected() -> None:
    text = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": pkg()}})

    with pytest.raises(LockfileParseError, match="no root package entry"):
        parse_lockfile(text)


def test_empty_packages_object_is_rejected() -> None:
    text = json.dumps({"lockfileVersion": 3, "packages": {}})

    with pytest.raises(LockfileParseError, match="no root package entry"):
        parse_lockfile(text)


@pytest.mark.parametrize("root", [[], "text", 5, None, True])
def test_root_entry_must_be_an_object(root: Any) -> None:
    text = json.dumps({"lockfileVersion": 3, "packages": {"": root}})

    with pytest.raises(LockfileParseError, match="Root package entry must be an object"):
        parse_lockfile(text)


def test_minimal_root_entry_is_accepted() -> None:
    parsed = parse_lockfile(lockfile({}))

    assert parsed.nodes == ()
    assert parsed.root_dependencies == ()
