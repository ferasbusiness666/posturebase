import json
from pathlib import Path
import subprocess
from typing import Sequence

import pytest

from supabase_security_scanner.config import PROFILE_PATH_ENV
from supabase_security_scanner.mcp_install import InstallError, install_mcp_clients


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / ".env.posturebase"
    profile.write_text("SUPABASE_PROJECT_REF=test-project\n", encoding="utf-8")
    return profile


def test_codex_and_claude_installers_use_local_profile_path(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    commands: list[list[str]] = []

    def which(name: str) -> str | None:
        return {"codex": "C:/tools/codex.exe", "claude": "C:/tools/claude.exe"}.get(name)

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    results, errors = install_mcp_clients(
        ["codex", "claude"],
        profile_path=profile,
        python_executable=str(tmp_path / "python.exe"),
        which=which,
        runner=runner,
    )

    assert errors == []
    assert [result.client for result in results] == ["codex", "claude"]
    assert commands[0][1:5] == ["mcp", "add", "posturebase", "--env"]
    assert commands[1][1:7] == ["mcp", "add", "--scope", "user", "--transport", "stdio"]
    expected_env = f"{PROFILE_PATH_ENV}={profile.resolve()}"
    assert all(expected_env in command for command in commands)
    assert all("SUPABASE_ACCESS_TOKEN" not in " ".join(command) for command in commands)


def test_opencode_installer_merges_legacy_global_config(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    home = tmp_path / "home"
    config = home / ".config" / "opencode" / "opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"model": "provider/model", "mcp": {"existing": {"type": "remote", "url": "https://example.test"}}}),
        encoding="utf-8",
    )

    results, errors = install_mcp_clients(
        ["opencode"],
        profile_path=profile,
        python_executable=str(tmp_path / "python.exe"),
        home=home,
        which=lambda name: "C:/tools/opencode.exe" if name == "opencode" else None,
    )

    saved = json.loads(config.read_text(encoding="utf-8"))
    assert errors == []
    assert results[0].client == "opencode"
    assert saved["model"] == "provider/model"
    assert "existing" in saved["mcp"]
    assert saved["mcp"]["posturebase"]["enabled"] is True
    assert saved["mcp"]["posturebase"]["environment"][PROFILE_PATH_ENV] == str(profile.resolve())


def test_opencode_v2_installer_uses_mcp_servers_shape(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    home = tmp_path / "home"

    results, errors = install_mcp_clients(
        ["opencode"],
        profile_path=profile,
        home=home,
        which=lambda name: "C:/tools/opencode2.exe" if name == "opencode2" else None,
    )

    config = home / ".config" / "opencode" / "opencode.json"
    saved = json.loads(config.read_text(encoding="utf-8"))
    entry = saved["mcp"]["servers"]["posturebase"]
    assert errors == []
    assert results[0].client == "opencode"
    assert entry["type"] == "local"
    assert "enabled" not in entry
    assert entry["cwd"] == str(profile.parent)


def test_installer_requires_setup_profile(tmp_path: Path) -> None:
    with pytest.raises(InstallError, match="Run `posturebase setup` first"):
        install_mcp_clients(["codex"], profile_path=tmp_path / "missing.env")
