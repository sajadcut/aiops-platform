"""Read-only Cognia Machine Client / KB / Search acceptance probe.

Run from repository root:
    python -m scripts.verify_cognia_connection --query "gfpapi systemd runbook"

No Human login, writes, approval actions, or credential/token output.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any, Callable

from domain.contracts.config import settings
from integrations.cognia import CogniaAPIError, CogniaClient


def _safe_failure(exc: Exception) -> dict[str, Any]:
    # Deliberately avoid str(exc): HTTP transports can include sensitive URLs.
    if isinstance(exc, CogniaAPIError):
        return {
            "status": "failed",
            "http_status": exc.status_code,
            "provider_code": exc.code,
        }
    return {"status": "failed", "error_type": type(exc).__name__}


async def run_probe(
    *,
    query: str,
    require_results: bool = False,
    test_context: bool = False,
    client_factory: Callable[[], CogniaClient] = CogniaClient,
) -> tuple[dict[str, Any], int]:
    report: dict[str, Any] = {
        "provider": "cognia",
        "mode": "read_only_machine_client",
        "configured_kb_ids": list(settings.COGNIA_KNOWLEDGE_BASE_IDS),
        "auth": {"status": "not_run"},
        "knowledge_bases": [],
        "search": {"status": "not_run"},
        "context": {"status": "skipped", "reason": "not_requested"},
    }

    missing = [
        key for key, value in (
            ("COGNIA_BASE_URL", settings.COGNIA_BASE_URL),
            ("COGNIA_CLIENT_ID", settings.COGNIA_CLIENT_ID),
            ("COGNIA_CLIENT_SECRET", settings.COGNIA_CLIENT_SECRET),
            ("COGNIA_CLIENT_APPLICATION_ID", settings.COGNIA_CLIENT_APPLICATION_ID),
            ("COGNIA_KNOWLEDGE_BASE_IDS", settings.COGNIA_KNOWLEDGE_BASE_IDS),
        ) if not value
    ]
    if missing:
        report["configuration"] = {"status": "failed", "missing_keys": missing}
        return report, 2
    if not str(query or "").strip():
        report["configuration"] = {"status": "failed", "reason": "query_required"}
        return report, 2
    if test_context and not settings.COGNIA_CONTEXT_PROFILE_ID:
        report["context"] = {"status": "skipped", "reason": "context_profile_not_provisioned"}

    try:
        async with client_factory() as client:
            try:
                await client.verify_machine_auth()
                report["auth"] = {"status": "passed"}
            except Exception as exc:
                report["auth"] = _safe_failure(exc)
                return report, 2

            # KB identity/activity check uses only GET, not management operations.
            for kb_id in settings.COGNIA_KNOWLEDGE_BASE_IDS:
                try:
                    kb = await client.get_knowledge_base(kb_id)
                    report["knowledge_bases"].append({
                        "id": kb_id,
                        "status": "passed" if kb["isActive"] else "failed",
                        "active": kb["isActive"],
                    })
                except Exception as exc:
                    report["knowledge_bases"].append({
                        "id": kb_id,
                        **_safe_failure(exc),
                    })

            try:
                result = await client.search(
                    query, knowledge_base_ids=list(settings.COGNIA_KNOWLEDGE_BASE_IDS),
                    limit=5,
                )
                count = len(result["items"])
                report["search"] = {
                    "status": "passed" if count else "empty",
                    "result_count": count,
                    "next_page_available": bool(result.get("nextContinuationToken")),
                }
            except Exception as exc:
                report["search"] = _safe_failure(exc)

            if test_context and settings.COGNIA_CONTEXT_PROFILE_ID:
                try:
                    payload = await client.generate_context(
                        query,
                        context_profile_id=settings.COGNIA_CONTEXT_PROFILE_ID,
                        subject=None,
                    )
                    report["context"] = {
                        "status": "passed" if payload["isSufficient"] else "insufficient",
                        "is_sufficient": payload["isSufficient"],
                    }
                except Exception as exc:
                    report["context"] = _safe_failure(exc)
    except Exception as exc:
        report["client"] = _safe_failure(exc)
        return report, 2

    failed = (
        report["auth"]["status"] != "passed"
        or any(kb["status"] != "passed" for kb in report["knowledge_bases"])
        or report["search"]["status"] == "failed"
        or report["context"]["status"] == "failed"
    )
    if failed:
        return report, 2
    if require_results and report["search"]["status"] == "empty":
        return report, 3
    return report, 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Cognia acceptance check (no secrets or knowledge contents printed)"
    )
    parser.add_argument(
        "--query",
        default="gfpapi systemd incident runbook",
        help="Search phrase; never echoed or stored in probe output",
    )
    parser.add_argument(
        "--require-results",
        action="store_true",
        help="exit 3 when Search succeeds but returns no indexed knowledge chunks",
    )
    parser.add_argument(
        "--test-context",
        action="store_true",
        help="also call Context Generation if a real Context Profile ID is configured",
    )
    args = parser.parse_args()
    report, exit_code = asyncio.run(
        run_probe(
            query=args.query,
            require_results=args.require_results,
            test_context=args.test_context,
        )
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
