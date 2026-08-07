from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .redaction import redact_text


@dataclass(frozen=True)
class TableInfo:
    schema: str
    name: str
    kind: str
    rls_enabled: bool
    security_invoker: bool
    anon_select: bool
    anon_insert: bool
    anon_update: bool
    anon_delete: bool
    authenticated_select: bool
    authenticated_insert: bool
    authenticated_update: bool
    authenticated_delete: bool

    @property
    def resource(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def client_reachable(self) -> bool:
        return any(
            (
                self.anon_select,
                self.anon_insert,
                self.anon_update,
                self.anon_delete,
                self.authenticated_select,
                self.authenticated_insert,
                self.authenticated_update,
                self.authenticated_delete,
            )
        )


@dataclass(frozen=True)
class PolicyInfo:
    schema: str
    table: str
    name: str
    command: str
    roles: tuple[str, ...]
    permissive: bool
    using_expression: str | None
    check_expression: str | None

    @property
    def resource(self) -> str:
        return f"{self.schema}.{self.table}"


@dataclass(frozen=True)
class FunctionInfo:
    schema: str
    name: str
    identity_arguments: str
    security_definer: bool
    config: tuple[str, ...]
    anon_execute: bool
    authenticated_execute: bool

    @property
    def resource(self) -> str:
        return f"{self.schema}.{self.name}({self.identity_arguments})"


@dataclass(frozen=True)
class ExtensionInfo:
    name: str
    schema: str
    version: str


@dataclass(frozen=True)
class BucketInfo:
    name: str
    is_public: bool
    object_count: int
    file_size_limit: int | None
    allowed_mime_types: tuple[str, ...] | None


@dataclass
class DatabaseSnapshot:
    tables: list[TableInfo] = field(default_factory=list)
    policies: list[PolicyInfo] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    extensions: list[ExtensionInfo] = field(default_factory=list)
    buckets: list[BucketInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


_TABLE_QUERY = """
SELECT
    n.nspname AS schema_name,
    c.relname AS object_name,
    c.relkind AS object_kind,
    c.relrowsecurity AS rls_enabled,
    COALESCE(array_to_string(c.reloptions, ','), '') LIKE '%%security_invoker=true%%' AS security_invoker,
    has_table_privilege('anon', c.oid, 'SELECT') AS anon_select,
    has_table_privilege('anon', c.oid, 'INSERT') AS anon_insert,
    has_table_privilege('anon', c.oid, 'UPDATE') AS anon_update,
    has_table_privilege('anon', c.oid, 'DELETE') AS anon_delete,
    has_table_privilege('authenticated', c.oid, 'SELECT') AS authenticated_select,
    has_table_privilege('authenticated', c.oid, 'INSERT') AS authenticated_insert,
    has_table_privilege('authenticated', c.oid, 'UPDATE') AS authenticated_update,
    has_table_privilege('authenticated', c.oid, 'DELETE') AS authenticated_delete
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = ANY(%s)
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND NOT c.relispartition
ORDER BY n.nspname, c.relname
"""

_POLICY_QUERY = """
SELECT
    schemaname,
    tablename,
    policyname,
    cmd,
    roles,
    permissive,
    qual,
    with_check
FROM pg_policies
WHERE schemaname = ANY(%s)
ORDER BY schemaname, tablename, policyname
"""

_FUNCTION_QUERY = """
SELECT
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_function_identity_arguments(p.oid) AS identity_arguments,
    p.prosecdef AS security_definer,
    COALESCE(p.proconfig, ARRAY[]::text[]) AS function_config,
    has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
    has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated_execute
FROM pg_proc AS p
JOIN pg_namespace AS n ON n.oid = p.pronamespace
WHERE n.nspname = ANY(%s)
ORDER BY n.nspname, p.proname, identity_arguments
"""

_EXTENSION_QUERY = """
SELECT e.extname AS extension_name, n.nspname AS schema_name, e.extversion
FROM pg_extension AS e
JOIN pg_namespace AS n ON n.oid = e.extnamespace
ORDER BY e.extname
"""

_BUCKET_QUERY = """
SELECT
    b.id AS bucket_name,
    b.public AS is_public,
    COUNT(o.id)::integer AS object_count,
    b.file_size_limit,
    b.allowed_mime_types
FROM storage.buckets AS b
LEFT JOIN storage.objects AS o ON o.bucket_id = b.id
GROUP BY b.id, b.public, b.file_size_limit, b.allowed_mime_types
ORDER BY b.id
"""


class PostgresIntrospector:
    """Collect metadata only; none of these queries read application table rows."""

    def collect(self, database_url: str, schemas: tuple[str, ...] = ("public",)) -> DatabaseSnapshot:
        snapshot = DatabaseSnapshot()
        with psycopg.connect(database_url, connect_timeout=10, row_factory=dict_row) as connection:
            snapshot.tables = self._run(connection, _TABLE_QUERY, (list(schemas),), self._tables, snapshot)
            snapshot.policies = self._run(
                connection, _POLICY_QUERY, (list((*schemas, "storage")),), self._policies, snapshot
            )
            snapshot.functions = self._run(
                connection, _FUNCTION_QUERY, (list(schemas),), self._functions, snapshot
            )
            snapshot.extensions = self._run(connection, _EXTENSION_QUERY, (), self._extensions, snapshot)
            snapshot.buckets = self._run(connection, _BUCKET_QUERY, (), self._buckets, snapshot)
        return snapshot

    @staticmethod
    def _run(
        connection: psycopg.Connection[Any],
        query: str,
        params: tuple[Any, ...],
        converter: Any,
        snapshot: DatabaseSnapshot,
    ) -> list[Any]:
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return converter(cursor.fetchall())
        except Exception as error:  # A partial scan is more useful than no scan.
            snapshot.warnings.append(f"Database metadata check skipped: {redact_text(error)}")
            return []

    @staticmethod
    def _tables(rows: list[dict[str, Any]]) -> list[TableInfo]:
        return [
            TableInfo(
                schema=row["schema_name"],
                name=row["object_name"],
                kind=row["object_kind"],
                rls_enabled=bool(row["rls_enabled"]),
                security_invoker=bool(row["security_invoker"]),
                anon_select=bool(row["anon_select"]),
                anon_insert=bool(row["anon_insert"]),
                anon_update=bool(row["anon_update"]),
                anon_delete=bool(row["anon_delete"]),
                authenticated_select=bool(row["authenticated_select"]),
                authenticated_insert=bool(row["authenticated_insert"]),
                authenticated_update=bool(row["authenticated_update"]),
                authenticated_delete=bool(row["authenticated_delete"]),
            )
            for row in rows
        ]

    @staticmethod
    def _policies(rows: list[dict[str, Any]]) -> list[PolicyInfo]:
        return [
            PolicyInfo(
                schema=row["schemaname"],
                table=row["tablename"],
                name=row["policyname"],
                command=row["cmd"],
                roles=tuple(row["roles"] or ()),
                permissive=bool(row["permissive"]),
                using_expression=row["qual"],
                check_expression=row["with_check"],
            )
            for row in rows
        ]

    @staticmethod
    def _functions(rows: list[dict[str, Any]]) -> list[FunctionInfo]:
        return [
            FunctionInfo(
                schema=row["schema_name"],
                name=row["function_name"],
                identity_arguments=row["identity_arguments"],
                security_definer=bool(row["security_definer"]),
                config=tuple(row["function_config"] or ()),
                anon_execute=bool(row["anon_execute"]),
                authenticated_execute=bool(row["authenticated_execute"]),
            )
            for row in rows
        ]

    @staticmethod
    def _extensions(rows: list[dict[str, Any]]) -> list[ExtensionInfo]:
        return [
            ExtensionInfo(
                name=row["extension_name"], schema=row["schema_name"], version=row["extversion"]
            )
            for row in rows
        ]

    @staticmethod
    def _buckets(rows: list[dict[str, Any]]) -> list[BucketInfo]:
        return [
            BucketInfo(
                name=row["bucket_name"],
                is_public=bool(row["is_public"]),
                object_count=int(row["object_count"]),
                file_size_limit=row["file_size_limit"],
                allowed_mime_types=(
                    tuple(row["allowed_mime_types"]) if row["allowed_mime_types"] is not None else None
                ),
            )
            for row in rows
        ]
