from pathlib import Path

from supabase_security_scanner.config import ScanConfig


def test_config_loads_only_current_working_directory_dotenv(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".env").write_text(
        "SUPABASE_PROJECT_REF=local-project\nSUPABASE_SCANNER_SOURCE_DIR=source\n",
        encoding="utf-8",
    )
    for name in ("SUPABASE_PROJECT_REF", "SUPABASE_SCANNER_SOURCE_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)

    config = ScanConfig.from_environment()

    assert config.project_ref == "local-project"
    assert config.source_dir == Path("source")
