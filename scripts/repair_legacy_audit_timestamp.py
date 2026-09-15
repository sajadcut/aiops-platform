"""Safely repair the known legacy audit_events.created_at type drift.

This utility is intentionally narrow. It only handles the legacy schema where
all operational-persistence tables match the canonical f2b3c4d5e6f7 revision
except ``audit_events.created_at`` which is TEXT instead of TIMESTAMPTZ.

Dry-run (default):
    python scripts/repair_legacy_audit_timestamp.py --from-head g7h8i9j0k1l2

Apply repair + Alembic reconciliation + upgrade to head:
    python scripts/repair_legacy_audit_timestamp.py --from-head g7h8i9j0k1l2 --apply
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
from sqlalchemy import create_engine, text

from scripts.reconcile_legacy_database import (
    OPERATIONAL_REVISION,
    _alembic_config,
    _sync_database_url,
    inspect_database,
)


EXPECTED_MISMATCH = {
    "audit_events": {
        "created_at": {
            "expected": "timestamp with time zone",
            "actual": "text",
        }
    }
}


def _timestamp_profile(connection) -> dict[str, Any]:
    row_count = int(connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one())
    null_count = int(
        connection.execute(text("SELECT COUNT(*) FROM audit_events WHERE created_at IS NULL")).scalar_one()
    )
    timezone_missing_count = int(
        connection.execute(
            text(
                r"""
                SELECT COUNT(*)
                FROM audit_events
                WHERE created_at IS NOT NULL
                  AND btrim(created_at) !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
                """
            )
        ).scalar_one()
    )
    samples = [
        str(value)
        for value in connection.execute(
            text(
                "SELECT created_at FROM audit_events "
                "WHERE created_at IS NOT NULL ORDER BY created_at LIMIT 5"
            )
        ).scalars().all()
    ]

    castable = True
    savepoint = connection.begin_nested()
    try:
        connection.execute(
            text(
                "SELECT COUNT(created_at::timestamptz) "
                "FROM audit_events WHERE created_at IS NOT NULL"
            )
        ).scalar_one()
    except Exception:
        castable = False
    finally:
        savepoint.rollback()

    return {
        "row_count": row_count,
        "null_count": null_count,
        "timezone_missing_count": timezone_missing_count,
        "postgres_castable": castable,
        "sample_values": samples,
    }


def _safe_to_repair(report: dict[str, Any], profile: dict[str, Any]) -> bool:
    return bool(
        report.get("current_heads")
        and report.get("operational_column_mismatches") == EXPECTED_MISMATCH
        and report.get("approval_status_allows_consumed")
        and report.get("approval_conflict_target_valid")
        and report.get("checkpoint_conflict_target_valid")
        and all((report.get("operational_tables") or {}).values())
        and not report.get("legacy_archive_exists")
        and (report.get("vector_types") or {}).get("knowledge_documents.embedding") == "vector(1536)"
        and (report.get("vector_types") or {}).get("memory_entries.embedding") == "vector(1536)"
        and int(profile.get("null_count") or 0) == 0
        and int(profile.get("timezone_missing_count") or 0) == 0
        and bool(profile.get("postgres_castable"))
    )


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def repair(*, expected_legacy_head: str, apply: bool) -> int:
    engine = create_engine(_sync_database_url())
    try:
        with engine.connect() as connection:
            report = inspect_database(connection)
            profile = _timestamp_profile(connection)

        payload = {
            "current_heads": report.get("current_heads"),
            "expected_heads": report.get("expected_heads"),
            "operational_column_mismatches": report.get("operational_column_mismatches"),
            "approval_status_allows_consumed": report.get("approval_status_allows_consumed"),
            "approval_conflict_target_valid": report.get("approval_conflict_target_valid"),
            "checkpoint_conflict_target_valid": report.get("checkpoint_conflict_target_valid"),
            "audit_events_created_at": profile,
        }
        payload["safe_to_repair"] = _safe_to_repair(report, profile)
        _print(payload)

        current_heads = list(report.get("current_heads") or [])
        if current_heads != [expected_legacy_head]:
            raise RuntimeError(
                f"legacy_head_mismatch: expected {[expected_legacy_head]!r}, got {current_heads!r}"
            )
        if not payload["safe_to_repair"]:
            raise RuntimeError(
                "legacy_audit_timestamp_not_safely_repairable; review the dry-run report before any schema change"
            )
        if not apply:
            print(
                "Known legacy audit timestamp drift is safely repairable. "
                "Re-run with --apply to convert created_at, reconcile Alembic metadata and upgrade to head."
            )
            return 0

        with engine.begin() as connection:
            # Re-check the legacy head under the write transaction to avoid a
            # time-of-check/time-of-use metadata race.
            heads = [
                str(value)
                for value in connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            ]
            if heads != [expected_legacy_head]:
                raise RuntimeError(
                    f"legacy_head_changed_before_repair: expected {[expected_legacy_head]!r}, got {heads!r}"
                )

            connection.execute(text("ALTER TABLE audit_events ALTER COLUMN created_at DROP DEFAULT"))
            connection.execute(
                text(
                    "ALTER TABLE audit_events ALTER COLUMN created_at "
                    "TYPE TIMESTAMPTZ USING created_at::timestamptz"
                )
            )
            connection.execute(
                text("ALTER TABLE audit_events ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP")
            )
            connection.execute(text("ALTER TABLE audit_events ALTER COLUMN created_at SET NOT NULL"))

        with engine.connect() as connection:
            post_type_report = inspect_database(connection)
        if not post_type_report.get("operational_compatible"):
            _print(post_type_report)
            raise RuntimeError(
                "audit_timestamp_conversion_completed_but_operational_schema_is_not_canonical"
            )

        with engine.begin() as connection:
            result = connection.execute(
                text("UPDATE alembic_version SET version_num=:revision WHERE version_num=:legacy"),
                {"revision": OPERATIONAL_REVISION, "legacy": expected_legacy_head},
            )
            if result.rowcount != 1:
                raise RuntimeError(f"unexpected_alembic_version_rowcount:{result.rowcount}")
        print(f"Reconciled Alembic metadata: {expected_legacy_head} -> {OPERATIONAL_REVISION}")

        command.upgrade(_alembic_config(), "head")

        with engine.connect() as connection:
            final_report = inspect_database(connection)
        _print(final_report)
        if not final_report.get("already_current"):
            raise RuntimeError("upgrade_completed_but_database_head_is_still_not_current")
        print("Legacy audit timestamp repair and database reconciliation completed successfully.")
        return 0
    finally:
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely repair legacy audit_events.created_at TEXT drift"
    )
    parser.add_argument(
        "--from-head",
        required=True,
        help="Exact legacy revision currently stored in alembic_version",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the type repair, reconcile Alembic metadata and upgrade to repository head",
    )
    args = parser.parse_args()
    return repair(expected_legacy_head=str(args.from_head).strip(), apply=bool(args.apply))


if __name__ == "__main__":
    raise SystemExit(main())
