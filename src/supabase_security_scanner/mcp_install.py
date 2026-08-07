from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Sequence

from .config import PROFILE_PATH_ENV
from .redaction import redact_text


SERVER_NAME = "posturebase"
SERVER_MODULE = "supabase_security_scanner.mcp_server"


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallResult:
    client: str
    detail: str


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
Which = Callable[[str], str | None]


def install_mcp_clients(
    clients: Sequence[str],
    *,
    profile_path: Path,
    force: bool = False,
    python_executable: str | None = None,
    home: Path | None = None,
    which: Which = shutil.which,
    runner: Runner | None = None,
) -> tuple[list[InstallResult], list[str]]:
    profile = profile_path.expanduser().resolve()
    if not profile.is_file():
        raise InstallError(f"PostureBase profile not found: {profile}. Run `posturebase setup` first.")
    python = str(Path(python_executable or sys.executable).resolve())
    run = runner or _run_command
    requested = ("codex", "claude", "opencode") if "all" in clients else tuple(clients)
    results: list[InstallResult] = []
    errors: list[str] = []

    for client in requested:
        try:
            if client == "codex":
                results.append(_install_codex(profile, python, force, which, run))
            elif client == "claude":
                results.append(_install_claude(profile, python, force, which, run))
            elif client == "opencode":
                results.append(_install_opencode(profile, python, force, which, home or Path.home()))
            else:
                raise InstallError(f"Unsupported MCP client: {client}")
        except InstallError as error:
            errors.append(f"{client}: {error}")
    return results, errors


def _install_codex(profile: Path, python: str, force: bool, which: Which, run: Runner) -> InstallResult:
    executable = which("codex")
    if not executable:
        raise InstallError("Codex CLI was not found on PATH.")
    if force:
        _run_optional(run, [executable, "mcp", "remove", SERVER_NAME])
    command = [
        executable,
        "mcp",
        "add",
        SERVER_NAME,
        "--env",
        f"{PROFILE_PATH_ENV}={profile}",
        "--",
        python,
        "-m",
        SERVER_MODULE,
    ]
    _run_required(run, command)
    return InstallResult("codex", "Installed. Restart Codex, then run /mcp.")


def _install_claude(profile: Path, python: str, force: bool, which: Which, run: Runner) -> InstallResult:
    executable = which("claude")
    if not executable:
        raise InstallError("Claude Code was not found on PATH.")
    if force:
        _run_optional(run, [executable, "mcp", "remove", "--scope", "user", SERVER_NAME])
    command = [
        executable,
        "mcp",
        "add",
        "--scope",
        "user",
        "--transport",
        "stdio",
        "--env",
        f"{PROFILE_PATH_ENV}={profile}",
        SERVER_NAME,
        "--",
        python,
        "-m",
        SERVER_MODULE,
    ]
    _run_required(run, command)
    return InstallResult("claude", "Installed for your user account. Restart Claude Code, then run /mcp.")


def _install_opencode(
    profile: Path,
    python: str,
    force: bool,
    which: Which,
    home: Path,
) -> InstallResult:
    is_v2 = bool(which("opencode2"))
    if not is_v2 and not which("opencode"):
        raise InstallError("OpenCode was not found on PATH.")

    config_dir = home / ".config" / "opencode"
    config_path = config_dir / "opencode.json"
    jsonc_path = config_dir / "opencode.jsonc"
    if jsonc_path.is_file() and not config_path.is_file():
        raise InstallError(
            "A JSONC-only OpenCode config already exists. Add PostureBase manually or rename it to opencode.json."
        )
    data = _read_json_object(config_path)
    data.setdefault("$schema", "https://opencode.ai/config.json")
    mcp = data.setdefault("mcp", {})
    if not isinstance(mcp, dict):
        raise InstallError("OpenCode's `mcp` setting is not a JSON object.")

    if is_v2:
        servers = mcp.setdefault("servers", {})
        if not isinstance(servers, dict):
            raise InstallError("OpenCode V2's `mcp.servers` setting is not a JSON object.")
    else:
        servers = mcp

    if SERVER_NAME in servers and not force:
        return InstallResult("opencode", "Already installed. Use --force to update it.")

    entry: dict[str, object] = {
        "type": "local",
        "command": [python, "-m", SERVER_MODULE],
        "environment": {PROFILE_PATH_ENV: str(profile)},
    }
    if is_v2:
        entry["cwd"] = str(profile.parent)
    else:
        entry["enabled"] = True
    servers[SERVER_NAME] = entry
    _write_json_atomic(config_path, data)
    command_name = "opencode2" if is_v2 else "opencode"
    return InstallResult("opencode", f"Installed. Restart OpenCode, then run `{command_name} mcp list`.")


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )


def _run_required(run: Runner, command: Sequence[str]) -> None:
    try:
        result = run(command)
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallError(redact_text(error)) from error
    if result.returncode:
        detail = (result.stderr or result.stdout or "MCP installer command failed.").strip().splitlines()[-1]
        raise InstallError(redact_text(detail))


def _run_optional(run: Runner, command: Sequence[str]) -> None:
    try:
        run(command)
    except (OSError, subprocess.SubprocessError):
        pass


def _read_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallError(f"Could not safely read OpenCode config: {redact_text(error)}") from error
    if not isinstance(value, dict):
        raise InstallError("OpenCode config must contain a JSON object.")
    return value


def _write_json_atomic(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=".opencode.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            json.dump(data, temporary, indent=2, ensure_ascii=False)
            temporary.write("\n")
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()
