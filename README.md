# Supabase Security Scanner

`supa-sec` is a deterministic, local, read-only security preflight for Supabase projects. It uses direct metadata queries, Management API configuration reads, and fixed source-code patterns. It does not use an LLM or automatically change a project.

## What the first release checks

- RLS disabled on `public` tables, RLS enabled with no policies, broad client grants, and risky policy patterns.
- Public Storage buckets, public buckets outside an allowlist, broad object policies, and missing bucket upload restrictions.
- Locally exposed Supabase secret/service-role keys, while never printing a detected secret.
- Auth configuration: email confirmation, password policy, redirect URLs, anonymous sign-in, and observed Auth rate limits.
- Risky exposed views, `SECURITY DEFINER` functions, extension placement, and selected database metadata hazards.

Each finding is structured JSON with a rule ID, severity, evidence, confidence, and a suggested remediation. Some configurations are intentionally contextual, so the scanner labels them as review findings instead of claiming they are universally vulnerable.

## Safety model

- Run only against projects you own or are authorized to assess.
- The scanner is read-only: it does not create, alter, or delete database objects.
- Keep `SUPABASE_DATABASE_URL` and `SUPABASE_ACCESS_TOKEN` in your local environment. They are never accepted as MCP tool arguments, written to reports, or committed.
- The source scan reports a path and line number, never a matched secret value.

## Local setup

Use `uv` to create the environment and install the project with its development dependencies. Copy `.env.example` to a local `.env`, fill it locally, and never commit it. The CLI loads a `.env` from its current working directory without overriding already-set process environment variables.

The required local values are:

- `SUPABASE_PROJECT_REF` for Management API Auth configuration.
- `SUPABASE_DATABASE_URL` for read-only database metadata inspection.
- `SUPABASE_ACCESS_TOKEN` for the Supabase Management API.
- `SUPABASE_SCANNER_SOURCE_DIR` for optional local source scanning.

For the hackathon test project, use only a throwaway project and harmless fixture data.

## Interfaces

- `supa-sec scan` is the primary local CLI. It emits JSON by default and can write a local report file if requested.
- `supa-sec-mcp` is an optional local stdio MCP server. It has one no-argument tool, `get_security_findings`, and reads all sensitive configuration from its own local environment.

The MCP adapter is intentionally thin: the CLI and MCP tool run the same scanner core.
