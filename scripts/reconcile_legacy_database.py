"""Guarded reconciliation for a legacy Alembic head with canonical schema.

This utility is intentionally conservative. It never treats an unknown Alembic
revision as equivalent to the current repository by name alone. Before changing
``alembic_version`` it proves that the database structurally matches the last
canonical revision immediately before operational persistence was introduced:
``fix_embedding_001``.

Typical usage::

    python scripts/reconcile_legacy_database.py --from-head g7h8i9j0k1l2
    python scripts/reconcile_legacy_database.py --from-head g7h8i9j0k1l2 --apply

The first command is inspection-only. The second performs the metadata
reconciliation and then runs ``alembic upgrade head``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from database.migration_validation import expected_migration_heads
from domain.contracts.config import settings


BASELINE_REVISION = "fix_embedding_001"
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


def _sync_database_url() -> str:
    raw = str(settings.ALEMBIC_DATABASE_URL or settings.DATABASE_URL or "").strip()
    if not raw:
        raise RuntimeError("database_url_not_configured")
    if raw.startswith("postgresql+asyncpg://"):
        return raw.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
    return raw


def _alembic_config() -> Config:
    ini = Path(__file__).resolve().parents[1] / "database" / "migrations" / "alembic.ini"
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

    baseline_compatible = bool(
        len(current_heads) == 1
        and all(baseline_tables.values())
        and not any(operational_tables.values())
        and not archive_exists
        and vector_types["knowledge_documents.embedding"] == "vector(1536)"
        and vector_types["memory_entries.embedding"] == "vector(1536)"
    )

    return {
        "current_heads": current_heads,
        "expected_heads": expected_heads,
        "baseline_revision": BASELINE_REVISION,
        "baseline_tables": baseline_tables,
        "operational_tables": operational_tables,
        "vector_types": vector_types,
        "legacy_archive_exists": archive_exists,
        "baseline_compatible": baseline_compatible,
        "already_current": set(current_heads) == set(expected_heads),
    }


def _print_report(report: dict[str, Any]) -> None:
    print(json.dumps(report, indent=2, sort_keys=True, default=str))


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
        if current_heads == [BASELINE_REVISION]:
            if not apply:
                print("Baseline revision is canonical. Re-run with --apply to upgrade to head.")
                return 0
        else:
            if current_heads != [expected_legacy_head]:
                raise RuntimeError(
                    f"legacy_head_mismatch: expected {[expected_legacy_head]!r}, got {current_heads!r}"
                )
            if not report["baseline_compatible"]:
                raise RuntimeError(
                    "legacy_schema_not_equivalent_to_fix_embedding_001; refusing to rewrite alembic_version"
                )
            if not apply:
                print(
                    "Schema matches canonical fix_embedding_001 and no operational-persistence tables exist. "
                    "Re-run with --apply to reconcile and upgrade."
                )
                return 0

            with engine.begin() as connection:
                result = connection.execute(
                    text("UPDATE alembic_version SET version_num=:revision WHERE version_num=:legacy"),
                    {"revision": BASELINE_REVISION, "legacy": expected_legacy_head},
                )
                if result.rowcount != 1:
                    raise RuntimeError(f"unexpected_alembic_version_rowcount:{result.rowcount}")
            print(f"Reconciled Alembic metadata: {expected_legacy_head} -> {BASELINE_REVISION}")

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
