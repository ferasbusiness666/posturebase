from pathlib import Path

from supabase_security_scanner.source_scan import SourceScanner


def test_source_scanner_finds_secret_without_returning_value(tmp_path: Path) -> None:
    source = tmp_path / "src" / "client.ts"
    source.parent.mkdir()
    secret_value = "sb_secret_" + "abc12345678901234567890"
    source.write_text(f'const key = "{secret_value}";\n', encoding="utf-8")

    findings = SourceScanner().scan(tmp_path)

    assert len(findings) == 1
    serialized = findings[0].to_dict()
    assert serialized["id"] == "source-001"
    assert secret_value not in str(serialized)
    assert serialized["evidence"]["line"] == 1


def test_source_scanner_ignores_untracked_local_env_secret(tmp_path: Path) -> None:
    secret_value = "sb_secret_" + "abc12345678901234567890"
    (tmp_path / ".env").write_text(f"SUPABASE_SECRET_KEY={secret_value}\n", encoding="utf-8")

    assert SourceScanner().scan(tmp_path) == []


def test_candidate_files_includes_env_files_without_descending_into_excluded_directories(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SUPABASE_URL=https://example.supabase.co\n", encoding="utf-8")
    excluded_file = tmp_path / ".venv" / "leaked.ts"
    excluded_file.parent.mkdir()
    excluded_file.write_text("const ignored = true;\n", encoding="utf-8")

    candidates = SourceScanner._candidate_files(tmp_path)

    assert env_file in candidates
    assert excluded_file not in candidates
