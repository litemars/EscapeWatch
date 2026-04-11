from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Finding severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def sarif_level(self) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }[self]


class Confidence(enum.Enum):
    """Confidence level for a finding."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def multiplier(self) -> float:
        return {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.7,
            Confidence.LOW: 0.4,
        }[self]


class Category(enum.Enum):
    """Check category."""

    PRIVILEGES = "runtime-privileges"
    FILESYSTEM = "filesystem-mounts"
    NAMESPACES = "namespaces"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud-metadata"
    SOCKETS = "runtime-sockets"
    SECRETS = "secrets-exposure"


@dataclass
class Finding:
    """A single assessment finding."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    evidence: str
    why_it_matters: str
    remediation: str
    references: list[str] = field(default_factory=list)

    @property
    def weighted_score(self) -> float:
        return self.severity.weight * self.confidence.multiplier

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category.value,
            "evidence": self.evidence,
            "why_it_matters": self.why_it_matters,
            "remediation": self.remediation,
            "references": self.references,
            "weighted_score": self.weighted_score,
        }


@dataclass
class EnvironmentInfo:
    """Detected runtime environment details."""

    is_container: bool = False
    is_docker: bool = False
    is_kubernetes: bool = False
    is_containerd: bool = False
    is_host: bool = False
    is_rootless: bool = False
    kernel_version: str = ""
    cgroup_version: str = ""
    init_process: str = ""
    hostname: str = ""
    container_id: str = ""
    runtime_hints: list[str] = field(default_factory=list)
    namespace_ids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_container": self.is_container,
            "is_docker": self.is_docker,
            "is_kubernetes": self.is_kubernetes,
            "is_containerd": self.is_containerd,
            "is_host": self.is_host,
            "is_rootless": self.is_rootless,
            "kernel_version": self.kernel_version,
            "cgroup_version": self.cgroup_version,
            "init_process": self.init_process,
            "hostname": self.hostname,
            "container_id": self.container_id,
            "runtime_hints": self.runtime_hints,
            "namespace_ids": self.namespace_ids,
        }

    @property
    def summary(self) -> str:
        parts = []
        if self.is_kubernetes:
            parts.append("Kubernetes pod")
        elif self.is_docker:
            parts.append("Docker container")
        elif self.is_containerd:
            parts.append("containerd container")
        elif self.is_container:
            parts.append("container (unknown runtime)")
        else:
            parts.append("host")
        if self.is_rootless:
            parts.append("rootless")
        return ", ".join(parts)


@dataclass
class CategoryScore:
    """Aggregated score for a check category."""

    category: Category
    total_score: float = 0.0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


@dataclass
class AssessmentResult:
    """Complete assessment result."""

    environment: EnvironmentInfo
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_score(self) -> float:
        return sum(f.weighted_score for f in self.findings)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    def category_scores(self) -> dict[Category, CategoryScore]:
        scores: dict[Category, CategoryScore] = {}
        for f in self.findings:
            if f.category not in scores:
                scores[f.category] = CategoryScore(category=f.category)
            cs = scores[f.category]
            cs.total_score += f.weighted_score
            cs.finding_count += 1
            counter = f"{f.severity.name.lower()}_count"
            setattr(cs, counter, getattr(cs, counter) + 1)
        return scores

    @property
    def grade(self) -> str:
        s = self.total_score
        if s == 0:
            return "A"
        if s < 20:
            return "B"
        if s < 50:
            return "C"
        if s < 100:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "0.1.0",
            "environment": self.environment.to_dict(),
            "summary": {
                "total_score": self.total_score,
                "grade": self.grade,
                "finding_count": len(self.findings),
                "max_severity": self.max_severity.value if self.max_severity else None,
                "categories": {
                    cat.value: {
                        "total_score": cs.total_score,
                        "finding_count": cs.finding_count,
                    }
                    for cat, cs in self.category_scores().items()
                },
            },
            "findings": [f.to_dict() for f in self.findings],
        }
