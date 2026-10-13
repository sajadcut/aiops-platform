"""Persisted, read-only workflow activity feed for Incident Room.

Never changes workflow checkpoints, approvals, targets or execution decisions.
A dedicated short database transaction allows visibility while the orchestrator
is waiting on external MCP/LLM calls in another transaction/process.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import text
from apps.audit_service.postgres import PostgreSQLAuditStore
from database import AsyncSessionLocal
from domain.contracts.logging import logger

ANALYSIS_STAGES = ("context", "triage", "parallel_agents", "rca", "evaluator", "decision")
EXECUTION_STAGES = ("execution", "verification", "memory")
STAGES = ANALYSIS_STAGES + ("approval",) + EXECUTION_STAGES + ("end",)
PROVIDERS = {"vm_mcp", "zabbix", "elasticsearch", "prometheus", "kubernetes_api"}
AGENT_STAGES = {"agent:" + name for name in (
    "network", "vm", "application", "infrastructure", "dependency",
    "storage", "kubernetes", "database", "recovery", "security",
    "identity", "messaging", "change", "triage",
)}
_STATUSES = {"started", "completed", "failed", "skipped", "waiting"}


def progress_record(stage: str, status: str, *, detail: str = "", provider: str = "") -> dict:
    if stage not in STAGES and stage not in PROVIDERS and stage not in AGENT_STAGES and stage != "knowledge":
        raise ValueError("invalid_progress_stage")
    if status not in _STATUSES:
        raise ValueError("invalid_progress_status")
    if provider and provider not in PROVIDERS:
        raise ValueError("invalid_progress_provider")
    return {"stage": stage, "status": status, "provider": provider,
            "detail": detail[:100] if detail in {"queried", "unavailable", "error", "skipped", "not_configured"} else ""}


async def emit_progress(incident_id: str | None, stage: str, status: str,
                        *, detail: str = "", provider: str = "") -> None:
    """Best-effort progress, NOT durable operational decision evidence."""
    if not incident_id:
        return
    record = progress_record(stage, status, detail=detail, provider=provider)
    try:
        event = {
            "event_id": str(uuid4()), "event_type": "workflow_progress",
            "actor": "progress_observer", "incident_id": str(incident_id),
            "action": None, "status": status, "metadata": record,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        async def write_event():
            async with AsyncSessionLocal() as db:
                await PostgreSQLAuditStore(db).append(event)
        # Progress is observational: a slow progress DB write must not delay
        # MCP probes, an operator Approval or a governed execution.
        await asyncio.wait_for(write_event(), timeout=1.5)
    except Exception as exc:
        logger.warning("workflow_progress_record_failed", incident_id=str(incident_id),
                       stage=stage, error_type=type(exc).__name__)


def _safe_event(event: Mapping[str, Any]) -> dict | None:
    metadata = event.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    try:
        record = progress_record(str(metadata.get("stage") or ""),
                                 str(metadata.get("status") or ""),
                                 provider=str(metadata.get("provider") or ""),
                                 detail=str(metadata.get("detail") or ""))
    except ValueError:
        return None
    created = event.get("created_at")
    record["at"] = created.isoformat() if hasattr(created, "isoformat") else str(created or "")
    return record


def summarize_progress(events: list[Mapping[str, Any]], *, incident_status: str = "",
                       checkpoint_status: str = "", approval_status: str = "",
                       checkpoint_version: int | None = None) -> dict:
    """Only completed actual stages move the bar; no ETA or time-derived percent.

    Filtered events are already isolated by Incident ID on the database query.
    Statuses in this method are display-only. Execution authority ignores it.
    """
    ordered = sorted((v for v in (_safe_event(e) for e in events) if v),
                     key=lambda r: r["at"])
    phases = {}
    providers = {}
    agents = {}
    started_at = {}
    current = None
    for item in ordered:
        stage = item["stage"]
        if stage in AGENT_STAGES:
            agents[stage[6:]] = item
        elif stage in PROVIDERS or stage == "knowledge":
            providers[stage] = item
        else:
            if item["status"] == "started":
                started_at[stage] = item["at"]
            phases[stage] = {
                **item, "started_at": started_at.get(stage),
                "finished_at": item["at"] if item["status"] in {"completed", "failed"} else None,
            }
            if item["status"] == "started":
                current = stage
            elif current == stage:
                current = None
    analysis_done = sum(phases.get(step, {}).get("status") == "completed" for step in ANALYSIS_STAGES)
    execution_done = sum(phases.get(step, {}).get("status") == "completed" for step in EXECUTION_STAGES)
    approval_waiting = approval_status in {"pending", "approved"}
    terminal = checkpoint_status in {"completed", "failed"}
    if approval_waiting:
        current = "approval"
    elif approval_status == "consumed" and not terminal:
        current = current or "execution"
    elif terminal:
        current = None
    # A paused, fully reviewed approval is a finished analysis (not a stalled 90% bar).
    # Never turn pending Approval into a fabricated 100% when earlier nodes
    # are missing/failed. A normally completed analysis has six actual stages.
    if approval_waiting and analysis_done == len(ANALYSIS_STAGES):
        analysis_percent = 100
    elif checkpoint_status == "completed" and phases.get("end", {}).get("status") == "completed":
        # An evaluator can stop the graph before Decision, legitimately
        # skipping that branch. The completed attempt is terminal, not 83%
        # mysteriously stuck; count only stages that ran on that path.
        analysis_percent = 100
    else:
        analysis_percent = round(100 * analysis_done / len(ANALYSIS_STAGES))
    analysis_percent = min(analysis_percent, 100)
    return {
        "schema": "incident_progress.v1", "incident_status": incident_status,
        "checkpoint_status": checkpoint_status,
        "checkpoint_version": checkpoint_version,
        "approval_status": approval_status,
        "analysis_percent": analysis_percent,
        "analysis_completed": analysis_done,
        "analysis_total": (analysis_done if checkpoint_status == "completed" and
                           phases.get("end", {}).get("status") == "completed"
                           else len(ANALYSIS_STAGES)),
        "execution_percent": round(100 * execution_done / len(EXECUTION_STAGES)),
        "execution_completed": execution_done, "execution_total": len(EXECUTION_STAGES),
        "current_stage": current,
        "failed_stage": next(
            (key for key, row in reversed(list(phases.items()))
             if row["status"] == "failed"), None
        ),
        "stages": {k: phases[k] for k in STAGES if k in phases},
        "providers": {k: providers[k] for k in ("knowledge", *sorted(PROVIDERS)) if k in providers},
        "agents": {k: agents[k] for k in sorted(agents)},
        "started_at": next((x["at"] for x in ordered if x["stage"] == "context" and x["status"] == "started"), None),
        "last_event_at": ordered[-1]["at"] if ordered else None,
        "time_estimate_available": False,
        "percent_represents": "observed_stage_completion_not_elapsed_time",
    }


async def load_progress(incident_id: str) -> dict:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT event_id, metadata, created_at FROM (
              SELECT event_id, metadata, created_at FROM audit_events
              WHERE incident_id=:incident_id AND event_type='workflow_progress'
              ORDER BY created_at DESC, event_id DESC LIMIT 180
            ) e ORDER BY created_at, event_id
        """), {"incident_id": incident_id})).mappings().all()
        status = (await db.execute(text("""
            SELECT i.status::text AS incident_status, w.status AS checkpoint_status,
                   w.version AS checkpoint_version,
                   (SELECT a.status::text FROM approvals a WHERE a.incident_id=i.id
                    ORDER BY a.created_at DESC LIMIT 1) AS approval_status
            FROM incidents i LEFT JOIN workflow_checkpoints w ON w.incident_id=i.id
            WHERE i.id=:incident_id
        """), {"incident_id": incident_id})).mappings().first()
    if not status:
        return {}
    return summarize_progress([dict(row) for row in rows],
                              incident_status=str(status["incident_status"] or ""),
                              checkpoint_status=str(status["checkpoint_status"] or ""),
                              checkpoint_version=status["checkpoint_version"],
                              approval_status=str(status["approval_status"] or ""))
