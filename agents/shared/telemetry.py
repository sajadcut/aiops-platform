from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import Any, Dict


class AgentTelemetry:
    """Process-local operational counters for Agent behavior.

    Durable per-incident decisions remain in Audit/Workflow state. These counters
    provide lightweight runtime observability without adding a new external
    dependency; a Prometheus exporter can consume ``snapshot()`` later.
    """

    _lock = Lock()
    _data: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

    @classmethod
    def record(
        cls,
        agent: str,
        *,
        duration_seconds: float = 0.0,
        success: bool = True,
        parse_failure: bool = False,
        confidence: float | None = None,
        evidence_coverage: float | None = None,
        handoff_count: int = 0,
        disagreement: bool = False,
    ) -> None:
        with cls._lock:
            row = cls._data[agent]
            row["invocations"] += 1
            row["successes" if success else "failures"] += 1
            row["duration_seconds_total"] += max(0.0, duration_seconds)
            if parse_failure:
                row["parse_failures"] += 1
            if confidence is not None:
                row["confidence_total"] += max(0.0, min(1.0, confidence))
                if confidence < 0.55:
                    row["low_confidence"] += 1
            if evidence_coverage is not None:
                row["evidence_coverage_total"] += max(0.0, min(1.0, evidence_coverage))
            row["handoffs"] += max(0, handoff_count)
            if disagreement:
                row["disagreements"] += 1

    @classmethod
    def snapshot(cls) -> Dict[str, Dict[str, Any]]:
        with cls._lock:
            result: Dict[str, Dict[str, Any]] = {}
            for agent, raw in cls._data.items():
                invocations = int(raw.get("invocations", 0))
                result[agent] = {
                    "invocations": invocations,
                    "successes": int(raw.get("successes", 0)),
                    "failures": int(raw.get("failures", 0)),
                    "parse_failures": int(raw.get("parse_failures", 0)),
                    "low_confidence": int(raw.get("low_confidence", 0)),
                    "handoffs": int(raw.get("handoffs", 0)),
                    "disagreements": int(raw.get("disagreements", 0)),
                    "avg_duration_seconds": round(raw.get("duration_seconds_total", 0.0) / invocations, 4) if invocations else 0.0,
                    "avg_confidence": round(raw.get("confidence_total", 0.0) / invocations, 4) if invocations else 0.0,
                    "avg_evidence_coverage": round(raw.get("evidence_coverage_total", 0.0) / invocations, 4) if invocations else 0.0,
                }
            return result

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._data.clear()
