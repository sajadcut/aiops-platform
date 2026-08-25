from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from domain.contracts.logging import logger


class VerificationStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


class VerificationResult(BaseModel):
    status: VerificationStatus
    before_state: Dict[str, float]
    after_state: Dict[str, float]
    changes: List[str]
    confidence: float
    evidence_refs: List[str]
    message: str
    metric_directions: Dict[str, str] = Field(default_factory=dict)
    comparable_metrics: int = 0


class VerificationEngine:
    """Deterministic before/after verification over fresh operational Evidence.

    Metrics are not assumed to share the same direction. Error/latency/pressure
    metrics are better when lower, while availability/success/up/throughput are
    better when higher. Unknown metrics are not used to claim success.
    """

    LOWER_IS_BETTER = {
        "error_rate",
        "cpu_usage",
        "memory_usage",
        "latency",
        "packet_loss",
        "queue_depth",
    }
    HIGHER_IS_BETTER = {
        "availability",
        "success_rate",
        "up",
        "throughput",
    }

    @classmethod
    async def verify_action(
        cls,
        action_plan: str,
        service: str,
        before_context: Dict[str, Any],
        after_context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        logger.info("Verification started: service=%s", service)
        before_metrics = cls._extract_metrics(before_context)

        if after_context is None:
            return cls._inconclusive(
                before_metrics,
                {},
                cls._evidence_refs(before_context),
                "No post-execution context was supplied.",
            )

        after_metrics = cls._extract_metrics(after_context)
        if not before_metrics:
            return cls._inconclusive(
                {},
                after_metrics,
                cls._evidence_refs(after_context),
                "No pre-execution metrics were available.",
            )
        if not after_metrics:
            return cls._inconclusive(
                before_metrics,
                {},
                cls._evidence_refs(before_context),
                "No post-execution metrics were available.",
            )

        comparable_keys = sorted(set(before_metrics) & set(after_metrics))
        comparable_keys = [key for key in comparable_keys if cls._direction(key) is not None]
        if not comparable_keys:
            return cls._inconclusive(
                before_metrics,
                after_metrics,
                cls._evidence_refs(before_context) + cls._evidence_refs(after_context),
                "No comparable metrics with defined verification semantics were found.",
            )

        changes: List[str] = []
        improvements = 0
        regressions = 0
        unchanged = 0
        directions: Dict[str, str] = {}
        epsilon = 1e-9

        for key in comparable_keys:
            before_value = before_metrics[key]
            after_value = after_metrics[key]
            direction = cls._direction(key)
            assert direction is not None
            directions[key] = direction
            delta = after_value - before_value
            if abs(delta) <= epsilon:
                unchanged += 1
                changes.append(f"{key}: {before_value:.4f} -> {after_value:.4f} (unchanged)")
                continue

            improved = delta < 0 if direction == "lower_is_better" else delta > 0
            if improved:
                improvements += 1
                changes.append(
                    f"{key}: {before_value:.4f} -> {after_value:.4f} (improved; {direction})"
                )
            else:
                regressions += 1
                changes.append(
                    f"{key}: {before_value:.4f} -> {after_value:.4f} (worsened; {direction})"
                )

        comparable = len(comparable_keys)
        if regressions == 0 and improvements > 0:
            status = VerificationStatus.SUCCESS
            confidence = min(0.95, 0.75 + 0.05 * improvements + 0.02 * unchanged)
            message = (
                f"{improvements} comparable metrics improved, {unchanged} remained stable, "
                "and none regressed."
            )
        elif regressions > improvements:
            status = VerificationStatus.FAILED
            confidence = max(0.2, 0.55 - 0.08 * regressions)
            message = f"{regressions} comparable metrics regressed and {improvements} improved."
        elif improvements > regressions:
            status = VerificationStatus.PARTIAL
            confidence = 0.65
            message = (
                f"{improvements} comparable metrics improved, {regressions} regressed, "
                f"and {unchanged} remained stable."
            )
        elif improvements == 0 and regressions == 0:
            status = VerificationStatus.INCONCLUSIVE
            confidence = 0.35
            message = "Comparable metrics did not change; recovery could not be demonstrated."
        else:
            status = VerificationStatus.PARTIAL
            confidence = 0.50
            message = "The result is mixed and requires further observation."

        refs = cls._dedupe_refs(
            cls._evidence_refs(before_context) + cls._evidence_refs(after_context)
        )
        return VerificationResult(
            status=status,
            before_state=before_metrics,
            after_state=after_metrics,
            changes=changes,
            confidence=round(confidence, 4),
            evidence_refs=refs,
            message=message,
            metric_directions=directions,
            comparable_metrics=comparable,
        )

    @classmethod
    def _inconclusive(
        cls,
        before: Dict[str, float],
        after: Dict[str, float],
        refs: List[str],
        message: str,
    ) -> VerificationResult:
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            before_state=before,
            after_state=after,
            changes=[],
            confidence=0.0,
            evidence_refs=cls._dedupe_refs(refs),
            message=message,
            metric_directions={},
            comparable_metrics=0,
        )

    @classmethod
    def _direction(cls, metric: str) -> Optional[str]:
        if metric in cls.LOWER_IS_BETTER:
            return "lower_is_better"
        if metric in cls.HIGHER_IS_BETTER:
            return "higher_is_better"
        return None

    @classmethod
    def _extract_metrics(cls, context: Dict[str, Any]) -> Dict[str, float]:
        if not context:
            return {}
        samples: Dict[str, List[float]] = {}

        def add(name: str, value: Any) -> None:
            if value is None:
                return
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return
            samples.setdefault(name, []).append(numeric)

        summary = context.get("summary", {})
        if isinstance(summary, dict):
            add("error_rate", summary.get("error_rate"))
            add("cpu_usage", summary.get("avg_cpu"))
            add("memory_usage", summary.get("avg_memory"))
            add("latency", summary.get("latency"))
            add("availability", summary.get("availability"))
            add("success_rate", summary.get("success_rate"))
            add("throughput", summary.get("throughput"))

        live_evidence = context.get("live_evidence", {})
        evidence_items = live_evidence.get("evidence", []) if isinstance(live_evidence, dict) else []
        for item in evidence_items:
            raw = item.get("raw_data", {}) if isinstance(item, dict) else {}
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "").lower()
            value = raw.get("value")
            canonical = cls._canonical_metric_name(name)
            if canonical:
                add(canonical, value)

        return {
            name: sum(values) / len(values)
            for name, values in samples.items()
            if values
        }

    @staticmethod
    def _canonical_metric_name(name: str) -> Optional[str]:
        value = str(name or "").lower()
        if not value:
            return None
        if any(token in value for token in ("error_rate", "5xx", "http_error", "errors")):
            return "error_rate"
        if any(token in value for token in ("latency", "duration", "response_time")):
            return "latency"
        if any(token in value for token in ("packet_loss", "packetloss")):
            return "packet_loss"
        if any(token in value for token in ("queue_depth", "backlog", "consumer_lag")):
            return "queue_depth"
        if any(token in value for token in ("cpu", "processor")):
            return "cpu_usage"
        if any(token in value for token in ("memory", "mem_")):
            return "memory_usage"
        if any(token in value for token in ("availability", "uptime_ratio")):
            return "availability"
        if any(token in value for token in ("success_rate", "success_ratio")):
            return "success_rate"
        if value in {"up", "service_up", "instance_up"} or value.endswith("_up"):
            return "up"
        if any(token in value for token in ("throughput", "requests_per_second", "rps")):
            return "throughput"
        return None

    @staticmethod
    def _evidence_refs(context: Optional[Dict[str, Any]]) -> List[str]:
        if not context:
            return []
        live_evidence = context.get("live_evidence", {})
        refs: List[str] = []
        if isinstance(live_evidence, dict):
            for item in live_evidence.get("evidence", []):
                if isinstance(item, dict) and item.get("reference"):
                    refs.append(str(item["reference"]))
        return refs

    @staticmethod
    def _dedupe_refs(refs: List[str]) -> List[str]:
        return list(dict.fromkeys(str(ref) for ref in refs if ref))
