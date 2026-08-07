from __future__ import annotations

import subprocess
from pathlib import Path
import re

from .models import Finding, Severity


_EXCLUDED_DIRECTORIES = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".next"}
_SCANNED_SUFFIXES = {".env", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".json", ".yml", ".yaml"}
_MAX_FILE_SIZE_BYTES = 1_000_000
_SECRET_KEY_PATTERN = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{12,}\b")
_PUBLIC_SECRET_ENV_PATTERN = re.compile(
    r"(?im)^\s*(?:NEXT_PUBLIC|VITE|PUBLIC)_[A-Z0-9_]*(?:SUPABASE_)?(?:SERVICE_ROLE|SECRET)[A-Z0-9_]*\s*[=:]"
)
_LEGACY_SERVICE_KEY_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*['\"]?eyJ[A-Za-z0-9._-]{20,}"
)
_PLACEHOLDER_WORDS = {"example", "placeholder", "your_key", "your-key", "replace", "changeme", "not_a_real"}


class SourceScanner:
    """Fixed-pattern source inspection which deliberately omits matched values from findings."""

    def scan(self, root: Path) -> list[Finding]:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError(f"Source directory does not exist: {root}")
        tracked_files = self._tracked_files(root)
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for path in self._candidate_files(root):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            relative_path = path.relative_to(root).as_posix()
            is_env_file = path.name.startswith(".env")
            for match in _SECRET_KEY_PATTERN.finditer(content):
                if self._looks_like_placeholder(match.group(0)):
                    continue
                if is_env_file and relative_path not in tracked_files:
                    continue
                self._append(
                    findings,
                    seen,
                    Finding(
                        id="source-001",
                        severity=Severity.CRITICAL,
                        resource=f"source:{relative_path}",
                        category="source",
                        issue="Supabase secret key appears in source or a tracked environment file",
                        why_it_matters=(
                            "A secret key can bypass Row Level Security and must never reach source control "
                            "or client-delivered code."
                        ),
                        fix_suggestion="Revoke the exposed key, remove it from source control, and load a replacement only from server-side secrets.",
                        evidence={"path": relative_path, "line": self._line_number(content, match.start()), "signal": "sb_secret key pattern"},
                    ),
                )
            for match in _PUBLIC_SECRET_ENV_PATTERN.finditer(content):
                self._append(
                    findings,
                    seen,
                    Finding(
                        id="source-002",
                        severity=Severity.CRITICAL,
                        resource=f"source:{relative_path}",
                        category="source",
                        issue="A public client environment variable is named like a Supabase secret",
                        why_it_matters=(
                            "Public environment variables are bundled or otherwise visible to clients."
                        ),
                        fix_suggestion="Remove the value from client-visible configuration and rotate it if it was real.",
                        evidence={"path": relative_path, "line": self._line_number(content, match.start()), "signal": "public secret environment variable"},
                    ),
                )
            for match in _LEGACY_SERVICE_KEY_ASSIGNMENT.finditer(content):
                if is_env_file and relative_path not in tracked_files:
                    continue
                self._append(
                    findings,
                    seen,
                    Finding(
                        id="source-003",
                        severity=Severity.CRITICAL,
                        resource=f"source:{relative_path}",
                        category="source",
                        issue="Legacy Supabase service-role JWT appears in source",
                        why_it_matters="Service-role credentials bypass Row Level Security and grant broad database access.",
                        fix_suggestion="Revoke the exposed key and keep the replacement in a server-side secret store only.",
                        evidence={"path": relative_path, "line": self._line_number(content, match.start()), "signal": "legacy service-role JWT assignment"},
                    ),
                )
        return findings

    @staticmethod
    def _candidate_files(root: Path) -> list[Path]:
        candidates: list[Path] = []
        for path in root.rglob("*"):
            if any(part in _EXCLUDED_DIRECTORIES for part in path.parts):
                continue
            if not path.is_file() or path.suffix.lower() not in _SCANNED_SUFFIXES:
                continue
            try:
                if path.stat().st_size <= _MAX_FILE_SIZE_BYTES:
                    candidates.append(path)
            except OSError:
                continue
        return candidates

    @staticmethod
    def _tracked_files(root: Path) -> set[str]:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z"],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return set()
        if completed.returncode != 0:
            return set()
        return {item.decode("utf-8", errors="replace") for item in completed.stdout.split(b"\0") if item}

    @staticmethod
    def _looks_like_placeholder(value: str) -> bool:
        lower_value = value.lower()
        return any(word in lower_value for word in _PLACEHOLDER_WORDS)

    @staticmethod
    def _line_number(content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1

    @staticmethod
    def _append(findings: list[Finding], seen: set[tuple[str, int, str]], finding: Finding) -> None:
        key = (str(finding.evidence.get("path")), int(finding.evidence.get("line", 0)), finding.id)
        if key not in seen:
            seen.add(key)
            findings.append(finding)
