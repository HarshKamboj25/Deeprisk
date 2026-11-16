import json

import pytest

from deprisk.core.lockfile import LockfileParseError, parse_lockfile_text
from deprisk.core.models import DependencyScope


def make_lockfile(version: int = 3) -> str:
    data = {
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": version,
        "requires": True,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {"example": "^1.0.0"},
            },
            "node_modules/example": {"version": "1.2.3"},
            "node_modules/other/node_modules/example": {"version": "1.2.3"},
            "node_modules/@demo/scoped": {"version": "2.0.0"},
        },
    }
    return json.dumps(data)


@pytest.mark.parametrize("version", [2, 3])
def test_parses_supported_lockfile_versions(version: int) -> None:
    nodes = parse_lockfile_text(make_lockfile(version))

    assert len(nodes) == 3


def test_preserves_duplicate_package_install_paths() -> None:
    nodes = parse_lockfile_text(make_lockfile())
    examples = [node for node in nodes if node.name == "example"]

    assert len(examples) == 2
    assert examples[0].version == examples[1].version == "1.2.3"
    assert examples[0].install_path != examples[1].install_path


def test_extracts_scoped_package_name() -> None:
    nodes = parse_lockfile_text(make_lockfile())
    scoped = next(node for node in nodes if node.name == "@demo/scoped")

    assert scoped.version == "2.0.0"


def test_distinguishes_direct_and_nested_installations() -> None:
    nodes = parse_lockfile_text(make_lockfile())
    examples = {node.install_path: node for node in nodes if node.name == "example"}

    direct = examples["node_modules/example"]
    nested = examples["node_modules/other/node_modules/example"]

    assert direct.is_direct is True
    assert DependencyScope.PRODUCTION in direct.scopes

    assert nested.is_direct is False
    assert DependencyScope.PRODUCTION not in nested.scopes


def make_v1_lockfile() -> str:
    return json.dumps({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "requires": True,
        "dependencies": {
            "example": {
                "version": "1.2.3",
                "requires": {"nested": "^2.0.0"},
                "dependencies": {
                    "nested": {"version": "2.1.0"}
                },
            },
            "@demo/scoped": {"version": "2.0.0"},
        },
    })


def test_parses_npm_v1_nested_dependency_tree() -> None:
    nodes = parse_lockfile_text(make_v1_lockfile())
    by_path = {node.install_path: node for node in nodes}

    assert len(nodes) == 3
    assert by_path["node_modules/example"].version == "1.2.3"
    assert by_path["node_modules/example/node_modules/nested"].version == "2.1.0"
    assert by_path["node_modules/@demo/scoped"].version == "2.0.0"
    assert by_path["node_modules/example"].is_direct is True
    assert by_path["node_modules/example/node_modules/nested"].is_direct is False
    assert DependencyScope.UNKNOWN in by_path["node_modules/example"].scopes


def test_long_lockfile_version_is_bounded_in_error_message() -> None:
    long_version = "x" * 100_000
    data = json.loads(make_lockfile())
    data["lockfileVersion"] = long_version

    with pytest.raises(LockfileParseError) as exc_info:
        parse_lockfile_text(json.dumps(data))

    message = str(exc_info.value)
    assert len(message) < 200
    assert "..." in message
    assert "expected 1, 2 or 3" in message


def test_rejects_malformed_json() -> None:
    with pytest.raises(LockfileParseError, match="Invalid JSON"):
        parse_lockfile_text("{not valid json")


def test_rejects_missing_package_version() -> None:
    data = json.loads(make_lockfile())
    data["packages"]["node_modules/example"]["version"] = ""

    with pytest.raises(LockfileParseError, match="Missing package version"):
        parse_lockfile_text(json.dumps(data))


def test_rejects_workspace_link_before_workspace_path_regardless_of_entry_order() -> None:
    data = json.loads(make_lockfile())
    packages = data["packages"]

    data["packages"] = {
        "": packages[""],
        "packages/app": {"version": "1.0.0"},
        "node_modules/app": {"resolved": "packages/app", "link": True},
        **{path: entry for path, entry in packages.items() if path},
    }

    with pytest.raises(
        LockfileParseError,
        match="Linked package entries are not supported yet",
    ):
        parse_lockfile_text(json.dumps(data))
