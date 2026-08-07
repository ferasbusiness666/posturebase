from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .checks import analyze_auth_config, analyze_database
from .config import ScanConfig
from .database import DatabaseSnapshot, PostgresIntrospector
from .management_api import ManagementApiClient
from .models import ScanResult
from .redaction import redact_text
from .source_scan import SourceScanner


class DatabaseCollector(Protocol):
    def collect(self, database_url: str, schemas: tuple[str, ...] = ("public",)) -> DatabaseSnapshot: ...


class AuthConfigCollector(Protocol):
    def fetch_auth_config(self, project_ref: str, access_token: str) -> dict: ...


class SecurityScanner:
    """Orchestrates deterministic checks; it never changes the target project."""

    def __init__(
        self,
        database_collector: DatabaseCollector | None = None,
        auth_collector: AuthConfigCollector | None = None,
        source_scanner: SourceScanner | None = None,
    ) -> None:
        self.database_collector = database_collector or PostgresIntrospector()
        self.auth_collector = auth_collector or ManagementApiClient()
        self.source_scanner = source_scanner or SourceScanner()

    def scan(self, config: ScanConfig) -> ScanResult:
        result = ScanResult(project_ref=config.project_ref)
        result.metadata["mode"] = "read-only"

        if config.database_url:
            try:
                snapshot = self.database_collector.collect(config.database_url)
                result.findings.extend(analyze_database(snapshot, config))
                result.warnings.extend(snapshot.warnings)
                result.checks_run.extend(["database", "storage"])
            except Exception as error:
                result.warnings.append(f"Database scan unavailable: {redact_text(error)}")
        else:
            result.warnings.append("Database scan skipped: SUPABASE_DATABASE_URL is not set.")

        if config.project_ref and config.access_token:
            try:
                auth_config = self.auth_collector.fetch_auth_config(config.project_ref, config.access_token)
                auth_findings, rate_limits = analyze_auth_config(auth_config, config)
                result.findings.extend(auth_findings)
                result.metadata["auth_rate_limits"] = rate_limits
                result.checks_run.append("auth")
            except Exception as error:
                result.warnings.append(f"Auth configuration scan unavailable: {redact_text(error)}")
        else:
            result.warnings.append(
                "Auth configuration scan skipped: SUPABASE_PROJECT_REF and SUPABASE_ACCESS_TOKEN are required."
            )

        if config.source_dir:
            self._scan_source(Path(config.source_dir), result)
        else:
            result.warnings.append("Source scan skipped: SUPABASE_SCANNER_SOURCE_DIR is not set.")
        return result

    def _scan_source(self, source_dir: Path, result: ScanResult) -> None:
        try:
            result.findings.extend(self.source_scanner.scan(source_dir))
            result.checks_run.append("source")
        except Exception as error:
            result.warnings.append(f"Source scan unavailable: {redact_text(error)}")
