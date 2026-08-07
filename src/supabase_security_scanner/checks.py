from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .config import ScanConfig
from .database import DatabaseSnapshot
from .models import Finding, Severity


_UNCONDITIONAL_EXPRESSION = {"true", "(true)", "( true )"}


def analyze_database(snapshot: DatabaseSnapshot, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    policies_by_resource: dict[str, list[Any]] = {}
    for policy in snapshot.policies:
        policies_by_resource.setdefault(policy.resource, []).append(policy)

    for table in snapshot.tables:
        if table.kind in {"r", "p"}:
            policies = policies_by_resource.get(table.resource, [])
            if not table.rls_enabled:
                severity = Severity.HIGH if table.client_reachable else Severity.MEDIUM
                findings.append(
                    Finding(
                        id="rls-001",
                        severity=severity,
                        resource=table.resource,
                        category="database",
                        issue="RLS is disabled",
                        why_it_matters=(
                            "A table reachable by a client role can expose or accept rows without "
                            "row-level authorization."
                        ),
                        fix_suggestion="Enable RLS and add policies that match the application's ownership model.",
                        evidence={
                            "client_reachable": table.client_reachable,
                            "anon_privileges": _privileges(table, "anon"),
                            "authenticated_privileges": _privileges(table, "authenticated"),
                        },
                    )
                )
            elif not policies:
                findings.append(
                    Finding(
                        id="rls-002",
                        severity=Severity.MEDIUM,
                        resource=table.resource,
                        category="database",
                        issue="RLS is enabled but no policies exist",
                        why_it_matters=(
                            "This normally blocks client access. It can be intentional for backend-only "
                            "tables, but often causes an unexpected production access failure."
                        ),
                        fix_suggestion="Confirm the table is backend-only or add least-privilege RLS policies.",
                        evidence={"client_reachable": table.client_reachable},
                        confidence="medium",
                    )
                )

            if table.anon_insert or table.anon_update or table.anon_delete:
                findings.append(
                    Finding(
                        id="db-grant-001",
                        severity=Severity.MEDIUM,
                        resource=table.resource,
                        category="database",
                        issue="Anonymous role has write privileges",
                        why_it_matters=(
                            "If a matching RLS policy is permissive or RLS is disabled, unauthenticated "
                            "clients may modify data."
                        ),
                        fix_suggestion="Revoke unnecessary anon write grants and verify matching RLS policies.",
                        evidence={"anon_privileges": _privileges(table, "anon"), "rls_enabled": table.rls_enabled},
                        confidence="medium",
                    )
                )

        if table.kind in {"v", "m"} and table.client_reachable and not table.security_invoker:
            findings.append(
                Finding(
                    id="view-001",
                    severity=Severity.HIGH,
                    resource=table.resource,
                    category="database",
                    issue="Client-reachable view may bypass underlying RLS",
                    why_it_matters=(
                        "Views commonly execute with owner privileges unless configured to use the invoking "
                        "role's security context."
                    ),
                    fix_suggestion=(
                        "Use security_invoker for a Postgres 15+ view, revoke client access, or move the "
                        "view outside exposed schemas."
                    ),
                    evidence={"object_kind": table.kind},
                )
            )

    for policy in snapshot.policies:
        expressions = [value for value in (policy.using_expression, policy.check_expression) if value]
        normalized = {" ".join(expression.lower().split()) for expression in expressions}
        if normalized & _UNCONDITIONAL_EXPRESSION:
            findings.append(
                Finding(
                    id="policy-001",
                    severity=Severity.HIGH,
                    resource=policy.resource,
                    category="database",
                    issue="RLS policy contains an unconditional true expression",
                    why_it_matters=(
                        "The policy may allow every applicable role to access or modify every row."
                    ),
                    fix_suggestion="Replace the unconditional expression with an ownership or role-based predicate.",
                    evidence={"policy": policy.name, "command": policy.command, "roles": list(policy.roles)},
                )
            )
        joined = " ".join(expressions).lower()
        if "raw_user_meta_data" in joined or "user_metadata" in joined:
            findings.append(
                Finding(
                    id="policy-002",
                    severity=Severity.HIGH,
                    resource=policy.resource,
                    category="database",
                    issue="RLS policy appears to rely on user-editable metadata",
                    why_it_matters=(
                        "User metadata can be changed by the user and is unsafe for authorization decisions."
                    ),
                    fix_suggestion="Store authorization data in app metadata or protected database tables instead.",
                    evidence={"policy": policy.name, "command": policy.command},
                )
            )

    for function in snapshot.functions:
        if not function.security_definer:
            continue
        exposed = function.schema == "public"
        client_executable = function.anon_execute or function.authenticated_execute
        if exposed or client_executable:
            findings.append(
                Finding(
                    id="function-001",
                    severity=Severity.HIGH if client_executable else Severity.MEDIUM,
                    resource=function.resource,
                    category="database",
                    issue="SECURITY DEFINER function is exposed or client executable",
                    why_it_matters=(
                        "A security-definer function runs with its owner's privileges and can bypass normal "
                        "authorization boundaries."
                    ),
                    fix_suggestion=(
                        "Move privileged functions to a private schema and revoke EXECUTE from client roles "
                        "unless explicitly required."
                    ),
                    evidence={
                        "schema": function.schema,
                        "anon_execute": function.anon_execute,
                        "authenticated_execute": function.authenticated_execute,
                    },
                )
            )
        if not any(item.startswith("search_path=") for item in function.config):
            findings.append(
                Finding(
                    id="function-002",
                    severity=Severity.MEDIUM,
                    resource=function.resource,
                    category="database",
                    issue="SECURITY DEFINER function does not set a search_path",
                    why_it_matters=(
                        "A mutable search path can make privileged database code resolve untrusted objects."
                    ),
                    fix_suggestion="Set a safe, explicit search_path in the function definition.",
                    evidence={"security_definer": True},
                )
            )

    for extension in snapshot.extensions:
        if extension.schema == "public":
            findings.append(
                Finding(
                    id="extension-001",
                    severity=Severity.LOW,
                    resource=f"extension:{extension.name}",
                    category="database",
                    issue="Database extension is installed in the public schema",
                    why_it_matters=(
                        "Extensions in an exposed schema can unnecessarily broaden the API surface."
                    ),
                    fix_suggestion="Review whether the extension can be installed in a dedicated private schema.",
                    evidence={"schema": extension.schema, "version": extension.version},
                    confidence="medium",
                )
            )

    for bucket in snapshot.buckets:
        if bucket.is_public and bucket.name not in config.public_bucket_allowlist:
            findings.append(
                Finding(
                    id="storage-001",
                    severity=Severity.MEDIUM if bucket.object_count else Severity.LOW,
                    resource=f"storage:{bucket.name}",
                    category="storage",
                    issue="Storage bucket is public and is not allowlisted",
                    why_it_matters=(
                        "Anyone who knows an object URL can retrieve files from a public bucket."
                    ),
                    fix_suggestion="Make the bucket private or explicitly allowlist it if public delivery is intended.",
                    evidence={"object_count": bucket.object_count, "public": True},
                    confidence="medium",
                )
            )
        if bucket.is_public and bucket.file_size_limit is None:
            findings.append(
                Finding(
                    id="storage-002",
                    severity=Severity.LOW,
                    resource=f"storage:{bucket.name}",
                    category="storage",
                    issue="Public Storage bucket has no file size limit",
                    why_it_matters=(
                        "Unbounded uploads can increase storage cost if a write policy permits uploads."
                    ),
                    fix_suggestion="Set a bucket file-size limit that matches the intended upload type.",
                    evidence={"public": True},
                    confidence="medium",
                )
            )

    for policy in snapshot.policies:
        if policy.schema != "storage" or policy.table != "objects":
            continue
        expressions = [value for value in (policy.using_expression, policy.check_expression) if value]
        normalized = {" ".join(expression.lower().split()) for expression in expressions}
        if policy.command in {"INSERT", "UPDATE", "DELETE", "ALL"} and normalized & _UNCONDITIONAL_EXPRESSION:
            findings.append(
                Finding(
                    id="storage-003",
                    severity=Severity.HIGH,
                    resource="storage.objects",
                    category="storage",
                    issue="Storage object policy permits writes with an unconditional expression",
                    why_it_matters=(
                        "A client role may be able to upload, overwrite, or delete objects without a bucket "
                        "or ownership restriction."
                    ),
                    fix_suggestion="Restrict the policy by bucket, operation, and authenticated owner where appropriate.",
                    evidence={"policy": policy.name, "command": policy.command, "roles": list(policy.roles)},
                )
            )

    return findings


def analyze_auth_config(auth_config: Mapping[str, Any], config: ScanConfig) -> tuple[list[Finding], dict[str, int]]:
    """Analyze only known, non-secret configuration fields from the Management API response."""

    findings: list[Finding] = []
    email_autoconfirm = _first(auth_config, "mailer_autoconfirm", "email_autoconfirm")
    if email_autoconfirm is True:
        findings.append(
            Finding(
                id="auth-001",
                severity=Severity.MEDIUM,
                resource="auth:email",
                category="auth",
                issue="Email confirmation is disabled",
                why_it_matters="Unverified email addresses can register accounts and receive authenticated access.",
                fix_suggestion="Require email confirmation unless your product has an explicit alternative verification flow.",
                evidence={"mailer_autoconfirm": True},
                confidence="medium",
            )
        )

    minimum_length = _as_int(_first(auth_config, "password_min_length", "minimum_password_length"))
    if minimum_length is not None and minimum_length < config.minimum_password_length:
        findings.append(
            Finding(
                id="auth-002",
                severity=Severity.MEDIUM,
                resource="auth:password-policy",
                category="auth",
                issue="Password minimum length is below the configured scanner policy",
                why_it_matters="Short passwords are easier to guess and increase account-takeover risk.",
                fix_suggestion=f"Set the minimum password length to at least {config.minimum_password_length} characters.",
                evidence={"configured_length": minimum_length, "scanner_minimum": config.minimum_password_length},
            )
        )

    leaked_password_protection = _first(auth_config, "password_hibp_enabled", "password_leaked_protection_enabled")
    if leaked_password_protection is False:
        findings.append(
            Finding(
                id="auth-003",
                severity=Severity.LOW,
                resource="auth:password-policy",
                category="auth",
                issue="Leaked-password protection is disabled",
                why_it_matters="Known compromised passwords make credential-stuffing attacks more likely to succeed.",
                fix_suggestion="Enable leaked-password protection when it is available for the project plan.",
                evidence={"leaked_password_protection": False},
                confidence="medium",
            )
        )

    anonymous_enabled = _first(auth_config, "external_anonymous_users_enabled", "anonymous_users_enabled")
    if anonymous_enabled is True:
        findings.append(
            Finding(
                id="auth-004",
                severity=Severity.LOW,
                resource="auth:anonymous",
                category="auth",
                issue="Anonymous sign-in is enabled",
                why_it_matters="Anonymous accounts can increase abuse and resource-consumption risk for public applications.",
                fix_suggestion="Confirm anonymous sign-in is needed and pair it with suitable abuse controls.",
                evidence={"anonymous_users_enabled": True},
                confidence="medium",
            )
        )

    site_url = _first(auth_config, "site_url")
    if isinstance(site_url, str) and site_url.startswith("http://") and "localhost" not in site_url:
        findings.append(
            Finding(
                id="auth-005",
                severity=Severity.MEDIUM,
                resource="auth:url-configuration",
                category="auth",
                issue="Production Site URL is not HTTPS",
                why_it_matters="Authentication redirects over HTTP can expose session-related links or tokens.",
                fix_suggestion="Use the HTTPS production origin as the Site URL.",
                evidence={"site_url": site_url},
            )
        )

    redirect_urls = _as_urls(_first(auth_config, "uri_allow_list", "redirect_urls"))
    for redirect_url in redirect_urls:
        if "*" in redirect_url:
            findings.append(
                Finding(
                    id="auth-006",
                    severity=Severity.MEDIUM,
                    resource="auth:url-configuration",
                    category="auth",
                    issue="Auth redirect allowlist contains a wildcard",
                    why_it_matters="Overly broad redirect patterns can send authentication flows to an unintended origin.",
                    fix_suggestion="Use the narrowest explicit production redirect URLs possible.",
                    evidence={"redirect_url": redirect_url},
                    confidence="medium",
                )
            )

    rate_limits = {
        key: value
        for key, raw_value in auth_config.items()
        if key.startswith("rate_limit_") and (value := _as_int(raw_value)) is not None
    }
    for key, maximum in config.max_auth_rate_limits.items():
        configured = rate_limits.get(key)
        if configured is not None and configured > maximum:
            findings.append(
                Finding(
                    id="auth-007",
                    severity=Severity.MEDIUM,
                    resource=f"auth:rate-limit:{key}",
                    category="auth",
                    issue="Auth rate limit exceeds the configured scanner policy",
                    why_it_matters="A high allowance can make abuse and account-enumeration attacks cheaper.",
                    fix_suggestion=f"Lower {key} to {maximum} or document why the higher value is needed.",
                    evidence={"configured_limit": configured, "scanner_maximum": maximum},
                    confidence="medium",
                )
            )
    return findings, rate_limits


def _privileges(table: Any, role: str) -> list[str]:
    return [
        operation.lower()
        for operation in ("select", "insert", "update", "delete")
        if getattr(table, f"{role}_{operation}")
    ]


def _first(config: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in config:
            return config[key]
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_urls(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.replace(",", " ").split() if item.strip()]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
