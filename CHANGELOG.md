# Changelog

## 0.1.0 - 2026-08-07

PostureBase's first public release.

### Added

- Deterministic, read-only checks for Supabase database metadata, RLS, Storage, Auth, rate limits, extensions, privileged functions, and local source files.
- Human-readable terminal reports and structured JSON output with stable rule IDs, severity, evidence, confidence, and remediation guidance.
- A guided local setup flow that stores credentials in an ignored `.env.posturebase` profile and verifies the connection.
- Local stdio MCP integration for Codex, Claude Code, and OpenCode without a hosted PostureBase service.
- Safe client installers that pass only the local profile path to each coding agent's configuration.
- Cross-platform automated tests on Windows and Linux with Python 3.11 and Python 3.14.

### Security model

- No AI is used to decide what is secure.
- Database inspection reads metadata rather than application table rows.
- Credentials are excluded from findings and reports.
- PostureBase never applies fixes or changes a Supabase project automatically.

### Install

```powershell
uv tool install "git+https://github.com/ferasbusiness666/posturebase.git@v0.1.0"
posturebase setup
posturebase scan --format text
```
