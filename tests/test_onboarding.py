from pathlib import Path

from dotenv import dotenv_values

from supabase_security_scanner.models import ScanResult
from supabase_security_scanner.onboarding import run_setup


class FakeScanner:
    def __init__(self) -> None:
        self.config = None

    def scan(self, config) -> ScanResult:
        self.config = config
        return ScanResult(
            project_ref=config.project_ref,
            checks_run=["database", "storage", "auth", "source"],
        )


def test_setup_uses_visible_credential_input_by_default(tmp_path: Path) -> None:
    profile = tmp_path / ".env.posturebase"
    database_url = "postgresql://postgres:secret-password@db.example.test:5432/postgres"
    access_token = "sbp_secret-test-token"
    visible_inputs = iter(["projectref1234567890", database_url, access_token, str(tmp_path)])
    output: list[str] = []
    scanner = FakeScanner()

    status = run_setup(
        profile_path=profile,
        project_dir=tmp_path,
        input_fn=lambda prompt: next(visible_inputs),
        secret_input_fn=lambda prompt: (_ for _ in ()).throw(AssertionError("hidden input was used")),
        output_fn=output.append,
        scanner_factory=lambda: scanner,
    )

    values = dotenv_values(profile)
    assert status == 0
    assert values["SUPABASE_PROJECT_REF"] == "projectref1234567890"
    assert values["SUPABASE_DATABASE_URL"] == database_url
    assert values["SUPABASE_ACCESS_TOKEN"] == access_token
    assert values["SUPABASE_SCANNER_SOURCE_DIR"] == str(tmp_path)
    assert scanner.config is not None
    rendered = "\n".join(output)
    assert "Credential input is VISIBLE" in rendered
    assert ".env.posturebase" in (tmp_path / ".gitignore").read_text(encoding="utf-8")


def test_setup_can_skip_network_verification(tmp_path: Path) -> None:
    visible_inputs = iter(
        [
            "projectref1234567890",
            "postgresql://user:pass@db.example.test/postgres",
            "sbp_token",
            str(tmp_path),
        ]
    )
    output: list[str] = []

    status = run_setup(
        project_dir=tmp_path,
        verify=False,
        input_fn=lambda prompt: next(visible_inputs),
        output_fn=output.append,
    )

    assert status == 0
    assert (tmp_path / ".env.posturebase").is_file()
    assert any("SKIP" in line for line in output)


def test_setup_can_hide_credential_input(tmp_path: Path) -> None:
    visible_inputs = iter(["projectref1234567890", str(tmp_path)])
    hidden_inputs = iter(["postgresql://user:pass@db.example.test/postgres", "sbp_token"])
    output: list[str] = []

    status = run_setup(
        project_dir=tmp_path,
        verify=False,
        hide_input=True,
        input_fn=lambda prompt: next(visible_inputs),
        secret_input_fn=lambda prompt: next(hidden_inputs),
        output_fn=output.append,
    )

    assert status == 0
    assert any("Credential input is hidden" in line for line in output)
