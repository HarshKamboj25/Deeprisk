"""Framework-independent domain models for DepRisk."""

from enum import StrEnum
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# The root project is a virtual graph location, not an installed package.
ROOT_INSTALL_PATH: Final = ""


class Ecosystem(StrEnum):
    NPM = "npm"


class DependencyScope(StrEnum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    PEER = "peer"
    UNKNOWN = "unknown"


class EdgeResolution(StrEnum):
    """Whether a declared dependency was found in the lockfile."""

    RESOLVED = "resolved"
    MISSING_OPTIONAL = "missing_optional"
    MISSING = "missing"


class AdvisorySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class DeclaredDependency(BaseModel):
    """A dependency declared in a manifest or lockfile entry, before resolution."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    requested_range: str
    scope: DependencyScope
    is_optional: bool = False


class DependencyNode(BaseModel):
    """One physical installation of a package in a scan."""

    model_config = ConfigDict(frozen=True)

    install_path: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    ecosystem: Ecosystem = Ecosystem.NPM
    scopes: frozenset[DependencyScope] = frozenset()
    is_direct: bool = False
    is_dev: bool = False
    declared_dependencies: tuple[DeclaredDependency, ...] = ()


class DependencyEdge(BaseModel):
    """A declared dependency from a parent install location.

    ``parent_path`` is ``ROOT_INSTALL_PATH`` ("") for the root project.
    ``child_path`` is the physical installation the dependency resolved to, and is
    ``None`` only when the dependency could not be resolved.
    """

    model_config = ConfigDict(frozen=True)

    parent_path: str
    child_path: str | None = Field(default=None, min_length=1)
    dependency_name: str = Field(min_length=1)
    requested_range: str | None = None
    scope: DependencyScope = DependencyScope.UNKNOWN
    is_optional: bool = False
    resolution: EdgeResolution = EdgeResolution.RESOLVED

    @model_validator(mode="after")
    def _check_resolution_consistency(self) -> Self:
        if self.resolution is EdgeResolution.RESOLVED:
            if self.child_path is None:
                raise ValueError("child_path is required when resolution is 'resolved'")
            return self

        if self.child_path is not None:
            raise ValueError(f"child_path must be None when resolution is '{self.resolution}'")
        if self.resolution is EdgeResolution.MISSING_OPTIONAL and not self.is_optional:
            raise ValueError("'missing_optional' requires is_optional=True")
        if self.resolution is EdgeResolution.MISSING and self.is_optional:
            raise ValueError("an optional dependency must use 'missing_optional', not 'missing'")
        return self


class ParsedLockfile(BaseModel):
    """Everything the graph builder needs from a lockfile."""

    model_config = ConfigDict(frozen=True)

    nodes: tuple[DependencyNode, ...]
    root_dependencies: tuple[DeclaredDependency, ...] = ()


class AdvisoryReference(BaseModel):
    """Normalized reference to a vulnerability advisory."""

    model_config = ConfigDict(frozen=True)

    advisory_id: str = Field(min_length=1)
    aliases: tuple[str, ...] = ()
    summary: str = ""
    severity: AdvisorySeverity = AdvisorySeverity.UNKNOWN
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    source: str = "OSV"


class FindingEvidence(BaseModel):
    """Evidence behind a vulnerability finding."""

    model_config = ConfigDict(frozen=True)

    kind: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source: str | None = None


class RiskAssessment(BaseModel):
    """Explainable, versioned risk assessment."""

    model_config = ConfigDict(frozen=True)

    score: float = Field(ge=0, le=100)
    confidence: str = "low"
    scoring_version: str = "v1"
    evidence: tuple[FindingEvidence, ...] = ()


class VulnerabilityFinding(BaseModel):
    """A vulnerability affecting one or more installed package instances."""

    model_config = ConfigDict(frozen=True)

    package_name: str = Field(min_length=1)
    package_version: str = Field(min_length=1)
    advisory: AdvisoryReference
    affected_install_paths: tuple[str, ...] = Field(min_length=1)
    risk: RiskAssessment | None = None
