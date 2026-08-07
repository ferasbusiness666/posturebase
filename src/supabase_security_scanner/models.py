from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A redacted, machine-readable result from one deterministic rule."""

    id: str
    severity: Severity
    resource: str
    issue: str
    why_it_matters: str
    fix_suggestion: str
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = "high"
    category: str = "general"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    project_ref: str | None = None
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            self.findings,
            key=lambda finding: (severity_order[finding.severity], finding.id, finding.resource),
        )
        return {
            "scanner": "supabase-security-scanner",
            "schema_version": "1.0",
            "scanned_at": self.scanned_at,
            "project_ref": self.project_ref,
            "findings": [finding.to_dict() for finding in sorted_findings],
            "warnings": self.warnings,
            "checks_run": self.checks_run,
            "metadata": self.metadata,
        }
