from pathlib import Path

from supabase_security_scanner.config import ScanConfig
from supabase_security_scanner.database import DatabaseSnapshot
from supabase_security_scanner.scanner import SecurityScanner


class FakeDatabase:
    def collect(self, database_url: str, schemas: tuple[str, ...] = ("public",)) -> DatabaseSnapshot:
        assert database_url == "postgresql://safe-local-test"
        return DatabaseSnapshot()


class FakeAuth:
    def fetch_auth_config(self, project_ref: str, access_token: str) -> dict:
        assert (project_ref, access_token) == ("project-ref", "local-token")
        return {"rate_limit_otp": 30}


def test_scanner_runs_configured_collectors(tmp_path: Path) -> None:
    result = SecurityScanner(database_collector=FakeDatabase(), auth_collector=FakeAuth()).scan(
        ScanConfig(
            project_ref="project-ref",
            database_url="postgresql://safe-local-test",
            access_token="local-token",
            source_dir=tmp_path,
        )
    )
    payload = result.to_dict()
    assert set(payload["checks_run"]) == {"database", "storage", "auth", "source"}
    assert payload["metadata"]["auth_rate_limits"] == {"rate_limit_otp": 30}
