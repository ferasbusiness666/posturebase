from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Callable
from urllib.parse import urlsplit

from dotenv import dotenv_values

from .config import ScanConfig, default_profile_path
from .scanner import SecurityScanner


Output = Callable[[str], None]
Input = Callable[[str], str]

_PROJECT_REF_PATTERN = re.compile(r"^[a-z0-9]{8,64}$")
_PROFILE_KEYS = (
    "SUPABASE_PROJECT_REF",
    "SUPABASE_DATABASE_URL",
    "SUPABASE_ACCESS_TOKEN",
    "SUPABASE_SCANNER_SOURCE_DIR",
)


class SetupError(ValueError):
    pass


def run_setup(
    *,
    profile_path: Path | None = None,
    project_dir: Path | None = None,
    verify: bool = True,
    hide_input: bool = False,
    input_fn: Input = input,
    secret_input_fn: Input = getpass.getpass,
    output_fn: Output = print,
    scanner_factory: Callable[[], SecurityScanner] = SecurityScanner,
) -> int:
    project = (project_dir or Path.cwd()).expanduser().resolve()
    profile = (profile_path or default_profile_path(project)).expanduser().resolve()
    existing = _existing_values(profile, project / ".env")

    output_fn("")
    output_fn("PostureBase Setup")
    output_fn("-----------------")
    output_fn("Local, read-only, and deterministic. Credentials never appear in reports.")
    if hide_input:
        output_fn("Credential input is hidden. A blank-looking line can still contain your paste.")
    else:
        output_fn("Credential input is VISIBLE so you can verify pasted values.")
        output_fn("Do not use this mode while screen sharing or recording the terminal.")
    output_fn("")

    credential_input = secret_input_fn if hide_input else input_fn

    project_ref = _prompt_value(
        "[1/4] Supabase project reference",
        existing.get("SUPABASE_PROJECT_REF"),
        input_fn,
    )
    database_url = _prompt_secret(
        "[2/4] Session Pooler database URL",
        existing.get("SUPABASE_DATABASE_URL"),
        credential_input,
    )
    access_token = _prompt_secret(
        "[3/4] Supabase personal access token",
        existing.get("SUPABASE_ACCESS_TOKEN"),
        credential_input,
    )
    default_source = existing.get("SUPABASE_SCANNER_SOURCE_DIR") or str(project)
    source_value = _prompt_value("[4/4] Local source directory", default_source, input_fn)
    source_dir = Path(source_value).expanduser()
    if not source_dir.is_absolute():
        source_dir = (project / source_dir).resolve()
    else:
        source_dir = source_dir.resolve()

    _validate_values(project_ref, database_url, access_token, source_dir)
    config = ScanConfig(
        project_ref=project_ref,
        database_url=database_url,
        access_token=access_token,
        source_dir=source_dir,
    )
    _write_profile(profile, config)
    _ensure_profile_is_ignored(project, profile)
    output_fn("")
    output_fn(f"OK  Saved local profile: {profile}")

    if not verify:
        output_fn("SKIP Connection verification was disabled.")
        _print_next_steps(output_fn)
        return 0

    output_fn("... Verifying the read-only database, Auth API, and source scan")
    result = scanner_factory().scan(config)
    required = {"database", "auth", "source"}
    completed = set(result.checks_run)
    missing = sorted(required - completed)
    if missing:
        output_fn(f"ERROR Setup saved, but verification could not run: {', '.join(missing)}")
        for warning in result.warnings:
            output_fn(f"      {warning}")
        output_fn("      Correct the value and run `posturebase setup` again.")
        return 1

    output_fn(f"OK  Connection verified. PostureBase found {len(result.findings)} finding(s).")
    for warning in result.warnings:
        output_fn(f"WARN {warning}")
    _print_next_steps(output_fn)
    return 0


def _existing_values(profile: Path, fallback: Path) -> dict[str, str]:
    source = profile if profile.is_file() else fallback
    if not source.is_file():
        return {}
    values = dotenv_values(source)
    return {key: value for key in _PROFILE_KEYS if isinstance((value := values.get(key)), str)}


def _prompt_value(label: str, existing: str | None, input_fn: Input) -> str:
    suffix = f" [{existing}]" if existing else ""
    value = input_fn(f"{label}{suffix}: ").strip()
    selected = value or existing
    if not selected:
        raise SetupError(f"{label} is required.")
    return selected


def _prompt_secret(label: str, existing: str | None, input_fn: Input) -> str:
    suffix = " [press Enter to keep the saved value]" if existing else ""
    value = input_fn(f"{label}{suffix}: ").strip()
    selected = value or existing
    if not selected:
        raise SetupError(f"{label} is required.")
    return selected


def _validate_values(project_ref: str, database_url: str, access_token: str, source_dir: Path) -> None:
    if not _PROJECT_REF_PATTERN.fullmatch(project_ref):
        raise SetupError("The project reference should contain only lowercase letters and numbers.")
    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise SetupError(
            "The database URL is incomplete or invalid. Paste the full Session Pooler URI from "
            "Supabase Connect. It should begin with postgresql:// or postgres:// and include "
            "@aws-REGION.pooler.supabase.com:5432/postgres. URL-encode special password characters."
        )
    if any(character.isspace() for character in access_token):
        raise SetupError("The personal access token cannot contain spaces.")
    if not source_dir.is_dir():
        raise SetupError(f"The source directory does not exist: {source_dir}")


def _write_profile(path: Path, config: ScanConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    values = {
        "SUPABASE_PROJECT_REF": config.project_ref or "",
        "SUPABASE_DATABASE_URL": config.database_url or "",
        "SUPABASE_ACCESS_TOKEN": config.access_token or "",
        "SUPABASE_SCANNER_SOURCE_DIR": str(config.source_dir or ""),
    }
    content = "# Generated by PostureBase. Keep this file private and never commit it.\n"
    content += "".join(f"{key}={json.dumps(value, ensure_ascii=False)}\n" for key, value in values.items())

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary_name = temporary.name
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _ensure_profile_is_ignored(project: Path, profile: Path) -> None:
    if profile.parent != project:
        return
    ignore_file = project / ".gitignore"
    existing = ignore_file.read_text(encoding="utf-8") if ignore_file.is_file() else ""
    rules = {line.strip() for line in existing.splitlines() if line.strip() and not line.startswith("#")}
    if profile.name in rules or ".env.*" in rules or ".env*" in rules:
        return
    separator = "" if not existing or existing.endswith("\n") else "\n"
    ignore_file.write_text(f"{existing}{separator}{profile.name}\n", encoding="utf-8")


def _print_next_steps(output_fn: Output) -> None:
    output_fn("")
    output_fn("Next:")
    output_fn("  posturebase scan --format text")
    output_fn("  posturebase mcp install codex")
    output_fn("  posturebase mcp install claude")
    output_fn("  posturebase mcp install opencode")
