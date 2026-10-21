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


def test_marks_direct_dependency() -> None:
    nodes = parse_lockfile_text(make_lockfile())
    direct = next(node for node in nodes if node.name == "example")

    assert direct.is_direct is True
    assert DependencyScope.PRODUCTION in direct.scopes


def test_rejects_unsupported_lockfile_version() -> None:
    with pytest.raises(LockfileParseError, match="Unsupported lockfileVersion"):
        parse_lockfile_text(make_lockfile(1))


def test_rejects_malformed_json() -> None:
    with pytest.raises(LockfileParseError, match="Invalid JSON"):
        parse_lockfile_text("{not valid json")


def test_rejects_missing_package_version() -> None:
    data = json.loads(make_lockfile())
    data["packages"]["node_modules/example"]["version"] = ""

    with pytest.raises(LockfileParseError, match="Missing package version"):
        parse_lockfile_text(json.dumps(data))
