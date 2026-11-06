"""Tests for package source identity and preserved npm source evidence."""

import json

import pytest
from pydantic import ValidationError

from deprisk.core.lockfile import parse_lockfile
from deprisk.core.models import (
    DependencyNode,
    PackageSourceType,
)


def parse_package(resolved=None, integrity=None, has_install_script=False):
    entry = {"version": "1.2.3"}

    if resolved is not None:
        entry["resolved"] = resolved
    if integrity is not None:
        entry["integrity"] = integrity
    if has_install_script:
        entry["hasInstallScript"] = True

    data = {
        "name": "fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture", "version": "1.0.0"},
            "node_modules/example": entry,
        },
    }

    parsed = parse_lockfile(json.dumps(data))
    return parsed.nodes[0]


def test_registry_url_is_classified_as_registry():
    node = parse_package(resolved="https://registry.npmjs.org/example/-/example-1.2.3.tgz")

    assert node.source_type is PackageSourceType.REGISTRY


@pytest.mark.parametrize(
    "url",
    [
        "git+https://github.com/example/project.git",
        "git+ssh://git@github.com/example/project.git",
        "git://github.com/example/project.git",
    ],
)
def test_git_sources_are_classified_as_git(url):
    node = parse_package(resolved=url)

    assert node.source_type is PackageSourceType.GIT


@pytest.mark.parametrize(
    "source",
    [
        "file:../example",
        "file:./packages/example",
        "file:/opt/packages/example",
    ],
)
def test_local_file_sources_are_classified_as_file(source):
    node = parse_package(resolved=source)

    assert node.source_type is PackageSourceType.FILE


def test_non_registry_https_url_is_classified_separately():
    node = parse_package(resolved="https://packages.example.com/example-1.2.3.tgz")

    assert node.source_type is PackageSourceType.URL


def test_missing_resolved_metadata_is_unknown():
    node = parse_package()

    assert node.source_type is PackageSourceType.UNKNOWN


def test_resolved_and_integrity_are_preserved():
    resolved = "https://registry.npmjs.org/example/-/example-1.2.3.tgz"
    integrity = "sha512-example-integrity"

    node = parse_package(resolved=resolved, integrity=integrity)

    assert node.resolved == resolved
    assert node.integrity == integrity


def test_install_script_metadata_is_preserved():
    node = parse_package(has_install_script=True)

    assert node.has_install_script is True


def test_install_script_defaults_to_false():
    node = parse_package()

    assert node.has_install_script is False


def test_source_type_enum_has_stable_values():
    assert {item.value for item in PackageSourceType} == {
        "registry",
        "git",
        "file",
        "url",
        "unknown",
    }


def test_dependency_node_source_evidence_is_immutable():
    node = DependencyNode(
        install_path="node_modules/example",
        name="example",
        version="1.2.3",
        source_type=PackageSourceType.REGISTRY,
        resolved="https://registry.npmjs.org/example/-/example-1.2.3.tgz",
        integrity="sha512-example",
        has_install_script=True,
    )

    with pytest.raises((ValidationError, TypeError)):
        node.source_type = PackageSourceType.GIT

    assert node.source_type is PackageSourceType.REGISTRY


@pytest.mark.parametrize(
    "url",
    [
        "https://registry.npmjs.org.attacker.com/example.tgz",
        "https://attacker.com/registry.npmjs.org/example.tgz",
    ],
)
def test_registry_lookalike_hosts_are_not_registry(url):
    node = parse_package(resolved=url)
    assert node.source_type is PackageSourceType.URL


@pytest.mark.parametrize(
    "url",
    [
        "https://registry.npmjs.org:8443/example.tgz",
        "https://user@registry.npmjs.org/example.tgz",
    ],
)
def test_registry_urls_with_nonstandard_authority_are_not_registry(url):
    node = parse_package(resolved=url)
    assert node.source_type is PackageSourceType.URL


def test_malformed_url_does_not_leak_value_error():
    node = parse_package(resolved="https://[invalid-ipv6/example.tgz")
    assert node.source_type is PackageSourceType.UNKNOWN


def test_git_shorthand_urls_are_classified_as_git():
    for url in (
        "github:owner/repository",
        "gitlab:owner/repository",
        "bitbucket:owner/repository",
    ):
        assert parse_package(resolved=url).source_type is PackageSourceType.GIT


@pytest.mark.parametrize(
    "url",
    [
        "https://registry.npmjs.org:443/example.tgz",
        "http://registry.npmjs.org:80/example.tgz",
    ],
)
def test_registry_default_ports_are_accepted(url):
    node = parse_package(resolved=url)
    assert node.source_type is PackageSourceType.REGISTRY
