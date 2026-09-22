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
    verification_policy: Optional[str] = None
    objective_results: List[Dict[str, Any]] = Field(default_factory=list)
    required_objectives_met: Optional[bool] = None


class VerificationEngine:
    """Deterministic before/after verification over fresh operational Evidence.

    Verification includes both directional metrics and structured operational
    conditions such as systemd state and the original TCP listener/reachability
    symptom. A successful write command is never sufficient by itself.
    """

    LOWER_IS_BETTER = {"error_rate", "cpu_usage", "memory_usage", "latency", "packet_loss", "queue_depth"}
    HIGHER_IS_BETTER = {
        "availability", "success_rate", "up", "throughput",
        "service_active", "port_listening", "tcp_reachable", "config_valid",
    }
    CRITICAL_OPERATIONAL_CONDITIONS = {"service_active", "port_listening", "tcp_reachable", "config_valid"}
    EXPECTED_RECOVERY_OVERHEAD = {"cpu_usage", "memory_usage"}

    @classmethod
    async def verify_action(
        cls,
        action_plan: str,
        service: str,
        before_context: Dict[str, Any],
        after_context: Optional[Dict[str, Any]] = None,
        verification_objectives: Optional[List[Dict[str, Any]]] = None,
    ) -> VerificationResult:
        logger.info("Verification started: service=%s", service)
        before_metrics = cls._extract_metrics(before_context)
        objectives = [item for item in (verification_objectives or []) if isinstance(item, dict)]
        if after_context is None:
            return cls._apply_objectives(
                cls._inconclusive(before_metrics, {}, cls._evidence_refs(before_context), "No post-execution context was supplied."),
                before_metrics, {}, objectives,
            )

        after_metrics = cls._extract_metrics(after_context)
        if not before_metrics:
            return cls._apply_objectives(
                cls._inconclusive({}, after_metrics, cls._evidence_refs(after_context), "No pre-execution metrics or operational conditions were available."),
                {}, after_metrics, objectives,
            )
        if not after_metrics:
            return cls._apply_objectives(
                cls._inconclusive(before_metrics, {}, cls._evidence_refs(before_context), "No post-execution metrics or operational conditions were available."),
                before_metrics, {}, objectives,
            )

        comparable_keys = sorted(set(before_metrics) & set(after_metrics))
        comparable_keys = [key for key in comparable_keys if cls._direction(key) is not None]
        if not comparable_keys:
            return cls._apply_objectives(
                cls._inconclusive(before_metrics, after_metrics, cls._evidence_refs(before_context) + cls._evidence_refs(after_context), "No comparable evidence with defined verification semantics was found."),
                before_metrics, after_metrics, objectives,
            )

        changes: List[str] = []
        improvements = 0
        regressions = 0
        unchanged = 0
        improved_keys: List[str] = []
        regressed_keys: List[str] = []
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
                improved_keys.append(key)
                changes.append(f"{key}: {before_value:.4f} -> {after_value:.4f} (improved; {direction})")
            else:
                regressions += 1
                regressed_keys.append(key)
                changes.append(f"{key}: {before_value:.4f} -> {after_value:.4f} (worsened; {direction})")

        operational = [key for key in comparable_keys if key in cls.CRITICAL_OPERATIONAL_CONDITIONS]
        unhealthy_after = [key for key in operational if after_metrics.get(key, 0.0) < 1.0]
        recovered_conditions = [key for key in operational if before_metrics.get(key, 1.0) < 1.0 and after_metrics.get(key, 0.0) >= 1.0]
        material_regressions = [key for key in regressed_keys if key not in cls.EXPECTED_RECOVERY_OVERHEAD]
        recovery_overhead = [key for key in regressed_keys if key in cls.EXPECTED_RECOVERY_OVERHEAD]
        comparable = len(comparable_keys)

        if unhealthy_after:
            status = VerificationStatus.FAILED
            confidence = 0.90 if any(key in {"port_listening", "tcp_reachable"} for key in unhealthy_after) else 0.80
            message = "Post-execution operational symptom remains unhealthy: " + ", ".join(sorted(unhealthy_after)) + "."
        elif recovered_conditions and not material_regressions:
            status = VerificationStatus.SUCCESS
            confidence = min(0.98, 0.88 + 0.02 * len(recovered_conditions))
            if recovery_overhead:
                confidence = max(0.80, confidence - 0.02 * len(recovery_overhead))
                message = (
                    "Operational recovery demonstrated for: "
                    + ", ".join(sorted(recovered_conditions))
                    + ". Expected post-recovery resource overhead observed for: "
                    + ", ".join(sorted(recovery_overhead))
                    + "."
                )
            else:
                message = "Operational recovery demonstrated for: " + ", ".join(sorted(recovered_conditions)) + "."
        elif recovered_conditions and material_regressions:
            status = VerificationStatus.PARTIAL
            confidence = 0.65
            message = (
                "Operational recovery was observed for: "
                + ", ".join(sorted(recovered_conditions))
                + ", but material regressions remain: "
                + ", ".join(sorted(material_regressions))
                + "."
            )
        elif regressions == 0 and improvements > 0:
            status = VerificationStatus.SUCCESS
            confidence = min(0.95, 0.75 + 0.05 * improvements + 0.02 * unchanged)
            message = f"{improvements} comparable metrics improved, {unchanged} remained stable, and none regressed."
        elif regressions > improvements:
            status = VerificationStatus.FAILED
            confidence = max(0.2, 0.55 - 0.08 * regressions)
            message = f"{regressions} comparable metrics regressed and {improvements} improved."
        elif improvements > regressions:
            status = VerificationStatus.PARTIAL
            confidence = 0.65
            message = f"{improvements} comparable metrics improved, {regressions} regressed, and {unchanged} remained stable."
        elif improvements == 0 and regressions == 0:
            status = VerificationStatus.INCONCLUSIVE
            confidence = 0.35
            message = "Comparable evidence did not change; recovery could not be demonstrated."
        else:
            status = VerificationStatus.PARTIAL
            confidence = 0.50
            message = "The result is mixed and requires further observation."

        refs = cls._dedupe_refs(cls._evidence_refs(before_context) + cls._evidence_refs(after_context))
        base_result = VerificationResult(
            status=status, before_state=before_metrics, after_state=after_metrics,
            changes=changes, confidence=round(confidence, 4), evidence_refs=refs,
            message=message, metric_directions=directions, comparable_metrics=comparable,
        )
        return cls._apply_objectives(
            base_result, before_metrics, after_metrics, objectives
        )

    @staticmethod
    def _objective_target(check: Dict[str, Any]) -> str:
        return str(
            check.get("metric")
            or check.get("signal")
            or check.get("state")
            or ""
        ).strip()

    @staticmethod
    def _expected_numeric(value: Any) -> Optional[float]:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            return None

    @classmethod
    def _apply_objectives(
        cls,
        result: VerificationResult,
        before: Dict[str, float],
        after: Dict[str, float],
        objectives: List[Dict[str, Any]],
    ) -> VerificationResult:
        if not objectives:
            return result

        rows: List[Dict[str, Any]] = []
        missing: List[str] = []
        failed: List[str] = []
        for check in objectives:
            target = cls._objective_target(check)
            direction = str(check.get("direction") or "").strip()
            expected = check.get("expected")
            present = target in after
            passed = False
            actual = after.get(target)
            reason = None

            if not target or not present:
                reason = "post_execution_objective_evidence_missing"
                if target:
                    missing.append(target)
            elif direction == "equals":
                expected_numeric = cls._expected_numeric(expected)
                if expected_numeric is None:
                    reason = "verification_objective_expected_value_invalid"
                else:
                    passed = abs(float(actual) - expected_numeric) <= 1e-9
                    if not passed:
                        reason = "verification_objective_not_met"
            elif direction == "absent":
                passed = abs(float(actual)) <= 1e-9
                if not passed:
                    reason = "verification_objective_not_absent"
            elif direction in {"lower_is_better", "higher_is_better"}:
                expected_text = str(expected or "").strip()
                expected_numeric = cls._expected_numeric(expected)
                if expected_text == "below_pre_action_baseline":
                    if target not in before:
                        reason = "pre_action_objective_evidence_missing"
                    else:
                        passed = float(actual) < float(before[target])
                elif expected_text == "above_pre_action_baseline":
                    if target not in before:
                        reason = "pre_action_objective_evidence_missing"
                    else:
                        passed = float(actual) > float(before[target])
                elif expected_numeric is not None:
                    passed = (
                        float(actual) <= expected_numeric
                        if direction == "lower_is_better"
                        else float(actual) >= expected_numeric
                    )
                elif target in before:
                    passed = (
                        float(actual) < float(before[target])
                        if direction == "lower_is_better"
                        else float(actual) > float(before[target])
                    )
                else:
                    reason = "verification_objective_threshold_missing"
                if not passed and reason is None:
                    reason = "verification_objective_not_met"
            else:
                reason = "verification_objective_direction_invalid"

            if present and not passed and reason not in {
                "post_execution_objective_evidence_missing",
                "pre_action_objective_evidence_missing",
            }:
                failed.append(target or "unknown")
            rows.append(
                {
                    "target": target or None,
                    "direction": direction or None,
                    "expected": expected,
                    "actual": actual,
                    "passed": passed,
                    "reason": reason,
                }
            )

        all_met = bool(rows) and all(bool(row.get("passed")) for row in rows)
        status = result.status
        confidence = result.confidence
        message = result.message
        if failed:
            status = VerificationStatus.FAILED
            confidence = max(confidence, 0.9)
            message = (
                "Runbook verification objectives failed: "
                + ", ".join(sorted(set(failed)))
                + ". "
                + message
            )
        elif missing:
            if status != VerificationStatus.FAILED:
                status = VerificationStatus.INCONCLUSIVE
                confidence = min(confidence, 0.4)
            message = (
                "Runbook verification objective evidence missing: "
                + ", ".join(sorted(set(missing)))
                + ". "
                + message
            )
        elif all_met and status == VerificationStatus.INCONCLUSIVE:
            status = VerificationStatus.SUCCESS
            confidence = max(confidence, 0.9)
            message = "All required runbook verification objectives were met. " + message

        return result.model_copy(
            update={
                "status": status,
                "confidence": round(float(confidence), 4),
                "message": message,
                "verification_policy": "runbook_required_objectives",
                "objective_results": rows,
                "required_objectives_met": all_met,
            }
        )
    @classmethod
    def _inconclusive(cls, before: Dict[str, float], after: Dict[str, float], refs: List[str], message: str) -> VerificationResult:
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE, before_state=before, after_state=after,
            changes=[], confidence=0.0, evidence_refs=cls._dedupe_refs(refs), message=message,
            metric_directions={}, comparable_metrics=0,
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
            if isinstance(value, bool):
                numeric = 1.0 if value else 0.0
            else:
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
            canonical = cls._canonical_metric_name(name)
            if canonical:
                add(canonical, raw.get("value"))

            diagnostic = str(raw.get("diagnostic") or "").strip().lower()
            if diagnostic == "service_status":
                active = raw.get("active_state") or raw.get("status")
                if active is not None:
                    add("service_active", str(active).lower() == "active")
                elif raw.get("healthy") is not None:
                    add("service_active", raw.get("healthy"))
            elif diagnostic == "port_listener_status" and raw.get("listening") is not None:
                add("port_listening", raw.get("listening"))
            elif diagnostic == "tcp_check" and raw.get("reachable") is not None:
                add("tcp_reachable", raw.get("reachable"))
            elif diagnostic == "config_validate" and raw.get("valid") is not None:
                add("config_valid", raw.get("valid"))

        return {name: sum(values) / len(values) for name, values in samples.items() if values}

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
