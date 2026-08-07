from pathlib import Path

from supabase_security_scanner.config import PROFILE_PATH_ENV, ScanConfig


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


def test_config_prefers_an_explicit_posturebase_profile(tmp_path: Path, monkeypatch) -> None:
    profile = tmp_path / ".env.posturebase"
    profile.write_text(
        "SUPABASE_PROJECT_REF=profile-project\n"
        "SUPABASE_DATABASE_URL=postgresql://profile.example/postgres\n"
        "SUPABASE_ACCESS_TOKEN=profile-token\n"
        "SUPABASE_SCANNER_SOURCE_DIR=.\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("SUPABASE_PROJECT_REF=fallback-project\n", encoding="utf-8")
    for name in (
        PROFILE_PATH_ENV,
        "SUPABASE_PROJECT_REF",
        "SUPABASE_DATABASE_URL",
        "SUPABASE_ACCESS_TOKEN",
        "SUPABASE_SCANNER_SOURCE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)

    config = ScanConfig.from_environment(profile_path=profile)

    assert config.project_ref == "profile-project"
    assert config.database_url == "postgresql://profile.example/postgres"
    assert config.access_token == "profile-token"
