# PostureBase

[![CI](https://github.com/ferasbusiness666/posturebase/actions/workflows/ci.yml/badge.svg)](https://github.com/ferasbusiness666/posturebase/actions/workflows/ci.yml)

PostureBase is a deterministic, local, read-only security scanner for Supabase projects. It checks database metadata, RLS policies, Storage, Auth configuration, rate-limit settings, and local source files. It does not use AI to decide what is secure, it does not host a backend, and it never changes your Supabase project.

PostureBase can run directly in a terminal or as a local MCP server for Codex, Claude Code, and OpenCode.

## Give this prompt to your coding agent

Copy the entire prompt below into Codex, Claude Code, or OpenCode. The agent can prepare the installation and configure its own MCP entry. You will enter the Supabase credentials yourself in a private terminal so they never need to be pasted into chat.

```text
Install and configure PostureBase locally for the coding agent you are currently running in.

Repository: https://github.com/ferasbusiness666/posturebase
Supported clients: Codex, Claude Code, and OpenCode.

Follow these requirements:
1. Determine which supported client you are running in and configure only that client.
2. Check for Git, Python 3.11 or newer, and uv. If something is missing, explain what is missing and request any approval needed before installing it from its official source.
3. Clone the repository into a folder named `posturebase` in the current working directory unless it is already present. Preserve existing files and never discard local changes.
4. Enter the repository and run `uv sync --extra dev`.
5. Run `uv run pytest` and report whether the tests pass.
6. Never ask me to paste a database password, connection string, or Supabase access token into chat, an agent tool call, or a command-line argument. Tell me to privately run `uv run posturebase setup --hide-input` in the repository. Explain that hidden credential input shows no characters and that I must paste each value and press Enter. Wait for me to confirm that setup says `OK Connection verified`.
7. After I confirm setup, run the matching command:
   - Codex: `uv run posturebase mcp install codex`
   - Claude Code: `uv run posturebase mcp install claude`
   - OpenCode: `uv run posturebase mcp install opencode`
8. Verify the saved MCP entry with `/mcp`, `claude mcp list`, or `opencode mcp list`, as appropriate. If an existing PostureBase entry is stale, rerun the installer with `--force` only after explaining why.
9. Tell me to completely restart the coding agent once. Explain that PostureBase is a local stdio MCP server: the agent starts it automatically from the saved configuration, so I do not need to keep a separate terminal or hosted server running.
10. After the restart, use PostureBase's `get_security_findings` MCP tool, summarize findings by severity, and do not change the Supabase project.
```

The agent cannot safely type the private Supabase values for you. That one setup command is the only manual credential step.

## What it checks

- RLS disabled on exposed tables and RLS enabled with no policies.
- Anonymous write grants and risky RLS policy expressions.
- Client-reachable views that may bypass RLS.
- Exposed `SECURITY DEFINER` functions and unsafe function search paths.
- Public Storage buckets, missing upload limits, and broad object-write policies.
- Supabase secret or service-role keys tracked in local client source files.
- Email confirmation, password length, leaked-password protection, anonymous sign-in, and redirect URLs.
- Auth rate limits, with optional project-specific maximums.
- Extensions installed in the exposed `public` schema.

Every finding includes a stable rule ID, severity, affected resource, evidence, confidence, and a suggested remediation.

## Before you start

You need:

1. Python 3.11 or newer.
2. [uv](https://docs.astral.sh/uv/) for the Python environment.
3. A Supabase project that you own or are authorized to scan.
4. These three Supabase values:
   - Project reference: the identifier shown in the project URL and dashboard.
   - Session Pooler database URL: open the Supabase dashboard, select **Connect**, choose **Session Pooler**, and copy the URI.
   - Personal access token: create one in your Supabase account access-token settings. This is a Management API token, not an anon key, publishable key, service-role key, or secret API key.

Use a test project while learning PostureBase. If the database password contains characters such as `@`, `#`, `/`, or `:`, use the correctly URL-encoded password in the database URI.

## 1. Install PostureBase

```powershell
git clone https://github.com/ferasbusiness666/posturebase.git
cd posturebase
uv sync --extra dev
```

No hosted service is created. Everything runs on your device.

## How the local MCP server works

PostureBase does not run continuously and does not need a hosted server.

1. The MCP installer saves a local command in your coding agent's configuration.
2. When the agent starts and connects to PostureBase, it launches the MCP server as a local child process.
3. The server reads the local `.env.posturebase` profile and communicates with the agent over stdio.
4. When the agent closes, the local MCP process stops. The saved configuration remains for future sessions.

After the first installation, you do not activate PostureBase manually for every session. You only need to reinstall the MCP entry if you move or delete the repository, replace its Python environment, or change the profile location. In that case, run the matching installer again with `--force`.

## 2. Run the secure setup

```powershell
uv run posturebase setup
```

The setup asks for four values:

1. Supabase project reference.
2. Session Pooler database URL.
3. Supabase personal access token.
4. The local source-code folder to scan.

The database URL and access token are visible while you type or paste them so you can verify the values. Do not run setup while screen sharing or recording your terminal. PostureBase saves them in `.env.posturebase`, adds that filename to `.gitignore` when necessary, and verifies the read-only connection. Rerun the same command whenever a password or token changes.

To hide the database URL and access-token input:

```powershell
uv run posturebase setup --hide-input
```

To save the profile while offline and verify later:

```powershell
uv run posturebase setup --no-verify
```

## 3. Run a scan

Readable terminal output:

```powershell
uv run posturebase scan --format text
```

Structured JSON output:

```powershell
uv run posturebase scan
```

Save a local JSON report:

```powershell
uv run posturebase scan --output security-findings.json
```

PostureBase only reads metadata and configuration. It does not enable RLS, edit policies, rotate keys, or apply fixes.

## 4. Connect an AI coding agent

Run one installer or install all detected clients:

```powershell
uv run posturebase mcp install codex
uv run posturebase mcp install claude
uv run posturebase mcp install opencode
uv run posturebase mcp install all
```

The agent configuration receives only:

- The local Python command that starts PostureBase.
- The path to `.env.posturebase`.

The database password and personal access token are not copied into Codex, Claude Code, or OpenCode configuration files.

You perform this installation once per coding client. Afterward, completely restart that client so it can launch the newly configured local server.

If a `posturebase` MCP entry already exists and you intentionally want to replace it:

```powershell
uv run posturebase mcp install codex --force
```

### Codex

After installation, completely restart Codex. Type `/mcp` and confirm that `posturebase` is connected. Codex desktop, the Codex CLI, and the IDE extension share the same local MCP configuration on a Codex host.

### Claude Code

After installation, restart Claude Code and run:

```powershell
claude mcp list
```

You can also type `/mcp` inside Claude Code. PostureBase is installed at Claude Code's private user scope, so it is available from any local project without committing an `.mcp.json` file.

### OpenCode

After installation, restart OpenCode and run:

```powershell
opencode mcp list
```

PostureBase uses OpenCode's own `mcp add` command to update the global configuration. OpenCode safely preserves existing settings and comments in either `opencode.json` or `opencode.jsonc`. The matching `opencode` or `opencode2` executable is detected automatically.

## 5. Ask the agent to scan

Use a prompt such as:

```text
Run the PostureBase security scan. Summarize the findings by severity and explain them. Do not change anything.
```

The agent calls one no-argument MCP tool named `get_security_findings`. Credentials cannot be supplied as tool arguments, and the tool cannot request arbitrary filesystem paths.

## Security model

- The scanner is deterministic; no LLM performs the security analysis.
- The MCP server uses local stdio. There is no PostureBase cloud server.
- Database queries inspect metadata and do not read application table rows.
- Management API access is limited to known configuration fields used by the scanner.
- Secrets are never included in findings or reports.
- Source findings report only the file path, line number, and detected secret type.
- PostureBase never applies fixes automatically.

## Common problems

### Database verification fails

- Confirm that you copied the **Session Pooler** URI, not an HTTP project URL.
- Replace the password placeholder with the actual database password.
- URL-encode special characters in the password.
- Confirm the project is running and your network can reach the pooler host.
- Rerun `uv run posturebase setup` after correcting the value.

### Auth configuration verification fails

- Confirm that the project reference is correct.
- Use a Supabase **personal access token** from your account settings.
- Do not use an anon key, publishable key, service-role key, or secret API key.
- Create a new personal access token if the old one was revoked, then rerun setup.

### The MCP server is not visible

1. Run the matching `posturebase mcp install ...` command again.
2. Completely restart the coding agent.
3. Check `/mcp`, `claude mcp list`, or `opencode mcp list`.
4. If an old entry points to a removed Python environment, reinstall with `--force`.

### I already have a `.env`

That is fine. New setups use the dedicated `.env.posturebase` profile. Existing installations that still use a project `.env` remain supported.

## Advanced scan options

Allow an intentionally public bucket:

```powershell
uv run posturebase scan --allow-public-bucket avatars
```

Flag an Auth rate limit above your own policy:

```powershell
uv run posturebase scan --max-rate-limit rate_limit_otp=30
```

Fail CI when a finding meets a severity threshold:

```powershell
uv run posturebase scan --fail-on high
```

The original `supa-sec` and `supa-sec-mcp` command names remain available as compatibility aliases.

## Development

Run the automated tests:

```powershell
uv run pytest
```

The MCP adapter is intentionally thin: the terminal command and all supported agents run the same scanner core.

## MCP configuration references

- [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)
- [OpenCode MCP documentation](https://opencode.ai/docs/mcp-servers/)
- [OpenCode V2 MCP documentation](https://opencode.ai/v2/docs/mcp-servers)
