from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


DEFAULT_PUBLIC_BUCKET_ALLOWLIST = frozenset({"avatars", "public-assets", "public_assets"})
PROFILE_PATH_ENV = "POSTUREBASE_CONFIG_PATH"
DEFAULT_PROFILE_NAME = ".env.posturebase"


def default_profile_path(base_dir: Path | None = None) -> Path:
    return (base_dir or Path.cwd()) / DEFAULT_PROFILE_NAME


@dataclass(frozen=True)
class ScanConfig:
    """Runtime configuration. Sensitive values are deliberately excluded from reports."""

    project_ref: str | None = None
    database_url: str | None = None
    access_token: str | None = None
    source_dir: Path | None = None
    public_bucket_allowlist: frozenset[str] = DEFAULT_PUBLIC_BUCKET_ALLOWLIST
    minimum_password_length: int = 8
    max_auth_rate_limits: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_environment(cls, profile_path: Path | None = None) -> "ScanConfig":
        # Process environment values always win. A dedicated PostureBase profile is
        # preferred, while the current project's .env remains a backwards-compatible
        # fallback. Parent directories are never searched.
        explicit_profile = profile_path
        if explicit_profile is None:
            configured_path = os.environ.get(PROFILE_PATH_ENV)
            explicit_profile = Path(configured_path).expanduser() if configured_path else None
        profile = explicit_profile or default_profile_path()
        if profile.is_file():
            load_dotenv(dotenv_path=profile, override=False)
        if explicit_profile is None:
            load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
        source_value = os.environ.get("SUPABASE_SCANNER_SOURCE_DIR")
        allowlist_value = os.environ.get("SUPABASE_SCANNER_PUBLIC_BUCKET_ALLOWLIST")
        allowlist = (
            frozenset(item.strip() for item in allowlist_value.split(",") if item.strip())
            if allowlist_value
            else DEFAULT_PUBLIC_BUCKET_ALLOWLIST
        )
        return cls(
            project_ref=os.environ.get("SUPABASE_PROJECT_REF") or None,
            database_url=os.environ.get("SUPABASE_DATABASE_URL") or None,
            access_token=os.environ.get("SUPABASE_ACCESS_TOKEN") or None,
            source_dir=Path(source_value).expanduser() if source_value else None,
            public_bucket_allowlist=allowlist,
        )

    def with_overrides(
        self,
        *,
        project_ref: str | None = None,
        source_dir: Path | None = None,
        public_bucket_allowlist: frozenset[str] | None = None,
        minimum_password_length: int | None = None,
        max_auth_rate_limits: dict[str, int] | None = None,
    ) -> "ScanConfig":
        return ScanConfig(
            project_ref=project_ref or self.project_ref,
            database_url=self.database_url,
            access_token=self.access_token,
            source_dir=source_dir if source_dir is not None else self.source_dir,
            public_bucket_allowlist=public_bucket_allowlist or self.public_bucket_allowlist,
            minimum_password_length=(
                minimum_password_length
                if minimum_password_length is not None
                else self.minimum_password_length
            ),
            max_auth_rate_limits=max_auth_rate_limits or self.max_auth_rate_limits,
        )
