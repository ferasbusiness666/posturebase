from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
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
                results.append(_install_opencode(profile, python, which, run))
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
        SERVER_NAME,
        "--env",
        f"{PROFILE_PATH_ENV}={profile}",
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
    which: Which,
    run: Runner,
) -> InstallResult:
    executable = which("opencode2") or which("opencode")
    if not executable:
        raise InstallError("OpenCode was not found on PATH.")
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
    command_name = Path(executable).stem
    return InstallResult(
        "opencode",
        f"Installed or updated. Restart OpenCode, then run `{command_name} mcp list`.",
    )


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
