"""Typed scanner result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    AFFECTED = "affected"
    PATCHED = "patched"
    UNKNOWN = "unknown"
    ERROR = "error"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, order=True)
class PhpVersion:
    major: int
    minor: int
    patch: int
    suffix: str = field(default="", compare=False)

    @property
    def branch(self) -> tuple[int, int]:
        return self.major, self.minor

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}{self.suffix}"


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    source: str


@dataclass(frozen=True)
class Finding:
    target: str
    status: Status
    confidence: Confidence
    summary: str
    detail: str
    version: str | None = None
    fixed_version: str | None = None
    cves: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    remediation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["confidence"] = self.confidence.value
        return data


@dataclass(frozen=True)
class ScanReport:
    mode: str
    findings: tuple[Finding, ...]
    errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def affected_count(self) -> int:
        return sum(item.status is Status.AFFECTED for item in self.findings)

    @property
    def unknown_count(self) -> int:
        return sum(item.status is Status.UNKNOWN for item in self.findings)

    def as_dict(self) -> dict[str, Any]:
        from . import __version__

        return {
            "schema_version": "1.0",
            "tool": {"name": "php2shell-audit", "version": __version__},
            "mode": self.mode,
            "summary": {
                "targets": len(self.findings),
                "affected": self.affected_count,
                "patched": sum(item.status is Status.PATCHED for item in self.findings),
                "unknown": self.unknown_count,
                "errors": len(self.errors),
            },
            "findings": [item.as_dict() for item in self.findings],
            "errors": list(self.errors),
            "notes": list(self.notes),
            "metadata": self.metadata,
        }
