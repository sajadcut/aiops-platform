from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from domain.contracts.config import settings


PEER_HANDOFF_AGENTS = {"database", "network", "dependency", "change"}


def _bounded_unique(values: Iterable[Any], limit: int) -> List[str]:
    result: List[str] = []
    for raw in values:
        value = str(raw).strip()
        if value and value not in result:
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _span_identity(span: Mapping[str, Any], index: int) -> Tuple[str, str, str]:
    trace_id = str(span.get("trace_id") or "unknown-trace")
    span_id = str(span.get("span_id") or f"anonymous-span-{index}")
    evidence_id = str(span.get("evidence_id") or f"anonymous-evidence-{index}")
    return trace_id, span_id, evidence_id


def build_trace_path_analysis(trace_analysis: Mapping[str, Any]) -> Dict[str, Any]:
    """Build bounded parent/child trace paths from the engine's normalized spans.

    The application engine intentionally emits bounded span candidates. This helper
    turns those candidates into causal path structure without pretending that a
    single longest span is automatically the end-to-end critical path. Missing
    parents remain explicit as incomplete paths.
    """
    raw_lists: Sequence[Any] = (
        trace_analysis.get("critical_path_candidates"),
        trace_analysis.get("slow_spans"),
        trace_analysis.get("error_spans"),
    )
    spans_by_trace: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for raw_list in raw_lists:
        if not isinstance(raw_list, list):
            continue
        for index, raw in enumerate(raw_list[:24]):
            if not isinstance(raw, Mapping):
                continue
            trace_id, span_id, evidence_id = _span_identity(raw, index)
            existing = spans_by_trace[trace_id].get(span_id)
            normalized = {
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": str(raw.get("parent_span_id")) if raw.get("parent_span_id") not in (None, "") else None,
                "evidence_id": evidence_id,
                "name": raw.get("name"),
                "caller": raw.get("caller"),
                "callee": raw.get("callee"),
                "duration_ms": raw.get("duration_ms"),
                "error": bool(raw.get("error")),
                "status": raw.get("status"),
            }
            if existing is None:
                spans_by_trace[trace_id][span_id] = normalized
            else:
                existing.update({key: value for key, value in normalized.items() if value not in (None, "", False)})
                existing["error"] = bool(existing.get("error")) or bool(normalized.get("error"))

    paths: List[Dict[str, Any]] = []
    for trace_id, spans in spans_by_trace.items():
        parent_ids = {str(span.get("parent_span_id")) for span in spans.values() if span.get("parent_span_id")}
        leaf_ids = [span_id for span_id in spans if span_id not in parent_ids]
        if not leaf_ids:
            leaf_ids = list(spans)[:1]

        for leaf_id in leaf_ids[:12]:
            chain: List[Dict[str, Any]] = []
            current_id: Optional[str] = leaf_id
            seen: Set[str] = set()
            path_complete = True
            while current_id and len(chain) < 16:
                if current_id in seen:
                    path_complete = False
                    break
                seen.add(current_id)
                span = spans.get(current_id)
                if span is None:
                    path_complete = False
                    break
                chain.append(span)
                parent_id = span.get("parent_span_id")
                if not parent_id:
                    break
                if str(parent_id) not in spans:
                    path_complete = False
                    break
                current_id = str(parent_id)
            chain.reverse()
            if not chain:
                continue

            numeric_durations: List[float] = []
            for span in chain:
                try:
                    if span.get("duration_ms") is not None:
                        numeric_durations.append(float(span["duration_ms"]))
                except (TypeError, ValueError):
                    continue
            services = _bounded_unique(
                [
                    value
                    for span in chain
                    for value in (span.get("caller"), span.get("callee"))
                    if value not in (None, "")
                ],
                12,
            )
            evidence_ids = _bounded_unique((span.get("evidence_id") for span in chain), 16)
            span_ids = _bounded_unique((span.get("span_id") for span in chain), 16)
            error_span_ids = _bounded_unique(
                (span.get("span_id") for span in chain if span.get("error")), 8
            )
            paths.append({
                "trace_id": trace_id,
                "span_ids": span_ids,
                "evidence_ids": evidence_ids,
                "services": services,
                "span_count": len(chain),
                "cumulative_span_duration_ms": round(sum(numeric_durations), 3) if numeric_durations else None,
                "max_span_duration_ms": round(max(numeric_durations), 3) if numeric_durations else None,
                "error_span_ids": error_span_ids,
                "terminal_span_id": str(chain[-1].get("span_id")),
                "terminal_service": chain[-1].get("callee") or chain[-1].get("caller"),
                "terminal_error": bool(chain[-1].get("error")),
                "path_complete": path_complete,
            })

    paths.sort(
        key=lambda row: (
            bool(row.get("terminal_error")),
            float(row.get("cumulative_span_duration_ms") or 0.0),
            float(row.get("max_span_duration_ms") or 0.0),
            int(row.get("span_count") or 0),
        ),
        reverse=True,
    )
    return {
        "policy": "parent_child_trace_structure_is_deterministic; path ranking is diagnostic evidence, not automatic root cause",
        "trace_count": len(spans_by_trace),
        "critical_path_candidates": paths[:8],
        "error_path_candidates": [row for row in paths if row.get("error_span_ids")][:8],
        "incomplete_path_count": sum(1 for row in paths if not row.get("path_complete")),
    }


def build_application_peer_context(
    context: Mapping[str, Any],
    live_evidence_ids: Iterable[str],
) -> Dict[str, Any]:
    """Extract Dependency/Change peer findings without promoting them to evidence.

    A peer finding is merely auxiliary analysis. Evidence-ID overlap only proves
    that the peer cited a live item available to this agent; it never proves the
    peer's causal statement or transfers its confidence.
    """
    live_ids = {str(value) for value in live_evidence_ids if str(value)}
    summary = context.get("summary") if isinstance(context, Mapping) else None
    peer = summary.get("peer_operational_context") if isinstance(summary, Mapping) else None
    if not isinstance(peer, Mapping):
        peer = {
            "findings": context.get("peer_findings") if isinstance(context.get("peer_findings"), list) else [],
            "coordination": context.get("agent_coordination") if isinstance(context.get("agent_coordination"), Mapping) else {},
        }

    findings: List[Dict[str, Any]] = []
    raw_findings = peer.get("findings") if isinstance(peer.get("findings"), list) else []
    for raw in raw_findings[: settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        agent_name = str(raw.get("agent_name") or "unknown").lower()
        cited_ids = _bounded_unique(raw.get("evidence_ids") or [], settings.AGENT_MAX_EVIDENCE_ITEMS)
        linked_ids = [value for value in cited_ids if value in live_ids]
        findings.append({
            "agent_name": agent_name,
            "statement": str(raw.get("statement") or "")[:520],
            "peer_confidence": raw.get("confidence"),
            "cited_evidence_ids": cited_ids,
            "live_linked_evidence_ids": linked_ids,
            "validation_status": "live_evidence_linked" if linked_ids else "unverified_peer_analysis",
            "hypotheses": list(raw.get("hypotheses") or [])[: settings.AGENT_MAX_HYPOTHESES],
            "missing_evidence": _bounded_unique(
                raw.get("missing_evidence") or [], settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES
            ),
        })

    dependency_findings = [
        row for row in findings if row.get("agent_name") in {"dependency", "database", "network"}
    ]
    change_findings = [row for row in findings if row.get("agent_name") == "change"]
    linked_handoffs: List[Dict[str, Any]] = []
    for row in findings:
        agent_name = str(row.get("agent_name") or "")
        linked_ids = list(row.get("live_linked_evidence_ids") or [])
        if agent_name in PEER_HANDOFF_AGENTS and linked_ids:
            linked_handoffs.append({
                "agent": agent_name,
                "reason": "peer analysis cites live evidence visible to ApplicationAgent; handoff is warranted for independent specialist validation",
                "evidence_ids": linked_ids,
            })

    coordination = peer.get("coordination") if isinstance(peer.get("coordination"), Mapping) else {}
    return {
        "policy": "peer_output_is_auxiliary_only; do_not_inherit_peer_confidence; evidence_id_overlap_validates_reference_not_causal_claim",
        "dependency_findings": dependency_findings,
        "change_findings": change_findings,
        "other_findings": [row for row in findings if row not in dependency_findings and row not in change_findings],
        "linked_handoff_candidates": linked_handoffs[:6],
        "coordination": {
            "agreement_score": coordination.get("agreement_score"),
            "disagreement": coordination.get("disagreement"),
            "contradictions": list(coordination.get("contradictions") or [])[: settings.AGENT_MAX_HYPOTHESES],
        },
    }
