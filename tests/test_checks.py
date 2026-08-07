from supabase_security_scanner.checks import analyze_auth_config, analyze_database
from supabase_security_scanner.config import ScanConfig
from supabase_security_scanner.database import (
    BucketInfo,
    DatabaseSnapshot,
    FunctionInfo,
    PolicyInfo,
    TableInfo,
)


def _table(*, rls_enabled: bool, name: str = "profiles") -> TableInfo:
    return TableInfo(
        schema="public",
        name=name,
        kind="r",
        rls_enabled=rls_enabled,
        security_invoker=False,
        anon_select=True,
        anon_insert=False,
        anon_update=False,
        anon_delete=False,
        authenticated_select=True,
        authenticated_insert=True,
        authenticated_update=True,
        authenticated_delete=True,
    )


def test_database_checks_disabled_rls_and_empty_policies() -> None:
    snapshot = DatabaseSnapshot(tables=[_table(rls_enabled=False), _table(rls_enabled=True, name="private_notes")])
    findings = analyze_database(snapshot, ScanConfig())
    by_id = {(finding.id, finding.resource) for finding in findings}
    assert ("rls-001", "public.profiles") in by_id
    assert ("rls-002", "public.private_notes") in by_id


def test_database_checks_dangerous_policies_and_functions() -> None:
    snapshot = DatabaseSnapshot(
        policies=[
            PolicyInfo(
                schema="public",
                table="profiles",
                name="everyone_can_read",
                command="SELECT",
                roles=("anon",),
                permissive=True,
                using_expression="true",
                check_expression=None,
            ),
            PolicyInfo(
                schema="public",
                table="profiles",
                name="metadata_role",
                command="SELECT",
                roles=("authenticated",),
                permissive=True,
                using_expression="auth.jwt() -> 'user_metadata' ->> 'role' = 'admin'",
                check_expression=None,
            ),
        ],
        functions=[
            FunctionInfo(
                schema="public",
                name="dangerous",
                identity_arguments="",
                security_definer=True,
                config=(),
                anon_execute=True,
                authenticated_execute=True,
            )
        ],
    )
    ids = {finding.id for finding in analyze_database(snapshot, ScanConfig())}
    assert {"policy-001", "policy-002", "function-001", "function-002"} <= ids


def test_storage_public_bucket_respects_allowlist() -> None:
    snapshot = DatabaseSnapshot(
        buckets=[
            BucketInfo("avatars", True, 2, None, None),
            BucketInfo("documents", True, 3, 1_000_000, ("application/pdf",)),
        ]
    )
    findings = analyze_database(snapshot, ScanConfig())
    assert any(finding.id == "storage-001" and finding.resource == "storage:documents" for finding in findings)
    assert not any(finding.id == "storage-001" and finding.resource == "storage:avatars" for finding in findings)


def test_auth_checks_are_policy_driven_and_rate_limit_aware() -> None:
    auth_config = {
        "mailer_autoconfirm": True,
        "password_min_length": 6,
        "site_url": "http://example.test",
        "uri_allow_list": "https://*.example.test https://app.example.test",
        "rate_limit_otp": 90,
    }
    config = ScanConfig(max_auth_rate_limits={"rate_limit_otp": 30})
    findings, rates = analyze_auth_config(auth_config, config)
    assert {finding.id for finding in findings} >= {"auth-001", "auth-002", "auth-005", "auth-006", "auth-007"}
    assert rates == {"rate_limit_otp": 90}
