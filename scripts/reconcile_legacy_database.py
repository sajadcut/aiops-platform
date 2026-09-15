"""Guarded reconciliation for a legacy Alembic head with canonical schema.

This utility is intentionally conservative. It never treats an unknown Alembic
revision as equivalent to a repository revision by name alone. It inspects the
actual PostgreSQL schema and only rewrites ``alembic_version`` when that schema
matches a known canonical point in the migration chain.

Typical usage::

    python scripts/reconcile_legacy_database.py --from-head g7h8i9j0k1l2
    python scripts/reconcile_legacy_database.py --from-head g7h8i9j0k1l2 --apply

The first command is inspection-only. The second performs metadata reconciliation
and then runs ``alembic upgrade head``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from database.migration_validation import expected_migration_heads
from domain.contracts.config import settings


BASELINE_REVISION = "fix_embedding_001"
OPERATIONAL_REVISION = "f2b3c4d5e6f7"
BASELINE_TABLES = {
    "incidents",
    "evidences",
    "findings",
    "knowledge_documents",
    "memory_entries",
}
OPERATIONAL_TABLES = {
    "approvals",
    "audit_events",
    "runbooks",
    "workflow_checkpoints",
}

OPERATIONAL_COLUMN_TYPES: dict[str, dict[str, str]] = {
    "approvals": {
        "approval_id": "uuid",
        "incident_id": "uuid",
        "action": "text",
        "risk_level": "character varying(50)",
        "approver": "character varying(255)",
        "status": "character varying(30)",
        "metadata": "jsonb",
        "created_at": "timestamp with time zone",
        "approved_at": "timestamp with time zone",
        "rejected_at": "timestamp with time zone",
    },
    "audit_events": {
        "event_id": "uuid",
        "event_type": "character varying(120)",
        "actor": "character varying(255)",
        "incident_id": "uuid",
        "action": "text",
        "status": "character varying(50)",
        "metadata": "jsonb",
        "created_at": "timestamp with time zone",
    },
    "runbooks": {
        "runbook_id": "uuid",
        "name": "character varying(255)",
        "version": "character varying(50)",
        "owner": "character varying(255)",
        "risk_level": "character varying(50)",
        "preconditions": "jsonb",
        "steps": "jsonb",
        "timeout_seconds": "integer",
        "rollback_steps": "jsonb",
        "enabled": "boolean",
        "created_at": "timestamp with time zone",
        "updated_at": "timestamp with time zone",
    },
    "workflow_checkpoints": {
        "incident_id": "uuid",
        "state": "jsonb",
        "status": "character varying(32)",
        "version": "bigint",
        "updated_at": "timestamp with time zone",
    },
}


def _sync_database_url() -> str:
    raw = str(settings.ALEMBIC_DATABASE_URL or settings.DATABASE_URL or "").strip()
    if not raw:
        raise RuntimeError("database_url_not_configured")
    if raw.startswith("postgresql+asyncpg://"):
        return raw.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
    return raw


def _alembic_config() -> Config:
    ini = PROJECT_ROOT / "database" / "migrations" / "alembic.ini"
    return Config(str(ini))


def _table_exists(connection, table_name: str) -> bool:
    value = connection.execute(
        text("SELECT to_regclass(:qualified_name)"),
        {"qualified_name": f"public.{table_name}"},
    ).scalar_one_or_none()
    return value is not None


def _column_type(connection, table_name: str, column_name: str) -> str | None:
    return connection.execute(
        text(
            """
            SELECT format_type(a.atttypid, a.atttypmod)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname = :table_name
              AND a.attname = :column_name
              AND a.attnum > 0
              AND NOT a.attisdropped
            """
        ),
        {"table_name": table_name, "column_name": column_name},
    ).scalar_one_or_none()


def _table_column_types(connection, table_name: str) -> dict[str, str]:
    if not _table_exists(connection, table_name):
        return {}
    rows = connection.execute(
        text(
            """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname = :table_name
              AND a.attnum > 0
              AND NOT a.attisdropped
            ORDER BY a.attnum
            """
        ),
        {"table_name": table_name},
    ).fetchall()
    return {str(name): str(column_type) for name, column_type in rows}


def _single_column_unique_or_primary(connection, table_name: str, column_name: str) -> bool:
    if not _table_exists(connection, table_name):
        return False
    return bool(
        connection.execute(
            text(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace n ON n.oid = rel.relnamespace
                    WHERE n.nspname = 'public'
                      AND rel.relname = :table_name
                      AND con.contype IN ('p', 'u')
                      AND cardinality(con.conkey) = 1
                      AND (
                          SELECT a.attname
                          FROM pg_attribute a
                          WHERE a.attrelid = rel.oid
                            AND a.attnum = con.conkey[1]
                      ) = :column_name
                )
                """
            ),
            {"table_name": table_name, "column_name": column_name},
        ).scalar_one()
    )


def _approval_status_constraints(connection) -> list[str]:
    if not _table_exists(connection, "approvals"):
        return []
    rows = connection.execute(
        text(
            """
            SELECT pg_get_constraintdef(con.oid)
            FROM pg_constraint con
            JOIN pg_class rel ON rel.oid = con.conrelid
            JOIN pg_namespace n ON n.oid = rel.relnamespace
            WHERE n.nspname = 'public'
              AND rel.relname = 'approvals'
              AND con.contype = 'c'
            ORDER BY con.conname
            """
        )
    ).scalars().all()
    return [str(value) for value in rows]


def _operational_column_mismatches(connection) -> dict[str, dict[str, dict[str, str | None]]]:
    mismatches: dict[str, dict[str, dict[str, str | None]]] = {}
    for table_name, expected_columns in OPERATIONAL_COLUMN_TYPES.items():
        actual_columns = _table_column_types(connection, table_name)
        table_mismatches: dict[str, dict[str, str | None]] = {}
        for column_name, expected_type in expected_columns.items():
            actual_type = actual_columns.get(column_name)
            if actual_type != expected_type:
                table_mismatches[column_name] = {
                    "expected": expected_type,
                    "actual": actual_type,
                }
        if table_mismatches:
            mismatches[table_name] = table_mismatches
    return mismatches


def inspect_database(connection) -> dict[str, Any]:
    current_rows = connection.execute(text("SELECT version_num FROM alembic_version")).fetchall()
    current_heads = sorted({str(row[0]) for row in current_rows})
    baseline_tables = {name: _table_exists(connection, name) for name in sorted(BASELINE_TABLES)}
    operational_tables = {name: _table_exists(connection, name) for name in sorted(OPERATIONAL_TABLES)}
    vector_types = {
        "knowledge_documents.embedding": _column_type(connection, "knowledge_documents", "embedding"),
        "memory_entries.embedding": _column_type(connection, "memory_entries", "embedding"),
    }
    archive_exists = _table_exists(connection, "legacy_knowledge_documents_archive")
    expected_heads = sorted(expected_migration_heads())

    pre_c3_core_compatible = bool(
        len(current_heads) == 1
        and all(baseline_tables.values())
        and not archive_exists
        and vector_types["knowledge_documents.embedding"] == "vector(1536)"
        and vector_types["memory_entries.embedding"] == "vector(1536)"
    )
    baseline_compatible = bool(pre_c3_core_compatible and not any(operational_tables.values()))

    operational_column_mismatches = _operational_column_mismatches(connection)
    approval_status_constraints = _approval_status_constraints(connection)
    approval_status_allows_consumed = any(
        "consumed" in definition.lower() and "status" in definition.lower()
        for definition in approval_status_constraints
    )
    approval_conflict_target_valid = _single_column_unique_or_primary(
        connection, "approvals", "approval_id"
    )
    checkpoint_conflict_target_valid = _single_column_unique_or_primary(
        connection, "workflow_checkpoints", "incident_id"
    )
    operational_compatible = bool(
        pre_c3_core_compatible
        and all(operational_tables.values())
        and not operational_column_mismatches
        and approval_status_allows_consumed
        and approval_conflict_target_valid
        and checkpoint_conflict_target_valid
    )

    equivalent_revision: str | None = None
    if baseline_compatible:
        equivalent_revision = BASELINE_REVISION
    elif operational_compatible:
        equivalent_revision = OPERATIONAL_REVISION

    return {
        "current_heads": current_heads,
        "expected_heads": expected_heads,
        "baseline_revision": BASELINE_REVISION,
        "operational_revision": OPERATIONAL_REVISION,
        "equivalent_revision": equivalent_revision,
        "baseline_tables": baseline_tables,
        "operational_tables": operational_tables,
        "vector_types": vector_types,
        "legacy_archive_exists": archive_exists,
        "baseline_compatible": baseline_compatible,
        "operational_compatible": operational_compatible,
        "operational_column_mismatches": operational_column_mismatches,
        "approval_status_constraints": approval_status_constraints,
        "approval_status_allows_consumed": approval_status_allows_consumed,
        "approval_conflict_target_valid": approval_conflict_target_valid,
        "checkpoint_conflict_target_valid": checkpoint_conflict_target_valid,
        "already_current": set(current_heads) == set(expected_heads),
    }


def _print_report(report: dict[str, Any]) -> None:
    print(json.dumps(report, indent=2, sort_keys=True, default=str))


def _rewrite_legacy_head(engine, *, legacy_head: str, canonical_revision: str) -> None:
    with engine.begin() as connection:
        result = connection.execute(
            text("UPDATE alembic_version SET version_num=:revision WHERE version_num=:legacy"),
            {"revision": canonical_revision, "legacy": legacy_head},
        )
        if result.rowcount != 1:
            raise RuntimeError(f"unexpected_alembic_version_rowcount:{result.rowcount}")
    print(f"Reconciled Alembic metadata: {legacy_head} -> {canonical_revision}")


def reconcile(*, expected_legacy_head: str, apply: bool) -> int:
    engine = create_engine(_sync_database_url())
    try:
        with engine.connect() as connection:
            report = inspect_database(connection)
        _print_report(report)

        if report["already_current"]:
            print("Database is already at the repository Alembic head.")
            return 0

        current_heads = report["current_heads"]
        canonical_current = current_heads in ([BASELINE_REVISION], [OPERATIONAL_REVISION])
        if canonical_current:
            canonical_revision = current_heads[0]
            if not apply:
                print(
                    f"Database is at canonical revision {canonical_revision}. "
                    "Re-run with --apply to upgrade to head."
                )
                return 0
        else:
            if current_heads != [expected_legacy_head]:
                raise RuntimeError(
                    f"legacy_head_mismatch: expected {[expected_legacy_head]!r}, got {current_heads!r}"
                )

            canonical_revision = report.get("equivalent_revision")
            if not canonical_revision:
                raise RuntimeError(
                    "legacy_schema_not_equivalent_to_supported_canonical_revision; "
                    "review operational_column_mismatches, approval constraints and conflict targets"
                )

            if not apply:
                print(
                    f"Schema matches canonical {canonical_revision}. "
                    "Re-run with --apply to reconcile Alembic metadata and upgrade to head."
                )
                return 0

            _rewrite_legacy_head(
                engine,
                legacy_head=expected_legacy_head,
                canonical_revision=str(canonical_revision),
            )

        command.upgrade(_alembic_config(), "head")

        with engine.connect() as connection:
            final_report = inspect_database(connection)
        _print_report(final_report)
        if not final_report["already_current"]:
            raise RuntimeError("upgrade_completed_but_database_head_is_still_not_current")
        if not all(final_report["operational_tables"].values()):
            raise RuntimeError("upgrade_completed_but_operational_persistence_schema_is_incomplete")
        print("Database reconciliation completed successfully.")
        return 0
    finally:
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely reconcile a legacy AIOps Alembic head")
    parser.add_argument(
        "--from-head",
        required=True,
        help="Exact legacy revision currently stored in alembic_version (for example g7h8i9j0k1l2)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the reconciliation and run alembic upgrade head. Without this flag the command is read-only.",
    )
    args = parser.parse_args()
    return reconcile(expected_legacy_head=str(args.from_head).strip(), apply=bool(args.apply))


if __name__ == "__main__":
    raise SystemExit(main())
