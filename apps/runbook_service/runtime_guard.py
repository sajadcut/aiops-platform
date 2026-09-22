from __future__ import annotations

from typing import Any, Dict, List

from apps.execution_service import ExecutionRequest, ExecutionService
from apps.remediation_planner import RemediationPlanner
from apps.verification_service import VerificationEngine, VerificationResult


class RunbookRuntimeGuard:
    """Live precondition and verification adapter for executable runbooks.

    Static runbook validation is necessary but not sufficient for production
    writes. This guard converts fresh read-only telemetry into the canonical
    Evidence shape used by RemediationPlanner and VerificationEngine.

    Only explicitly implemented runbook families are supported. A runbook with
    an execution contract must not silently skip dynamic runtime validation.
    """

    VM_SERVICE_RUNBOOK = RemediationPlanner.VM_SERVICE_RUNBOOK

    @staticmethod
    async def _vm_read(
        *,
        action: str,
        target: str,
        parameters: Dict[str, Any],
        incident_id: str,
    ):
        return await ExecutionService.execute(
            ExecutionRequest(
                tool_name="vm_telemetry",
                action=action,
                target=target,
                parameters=parameters,
                timeout=20,
                agent_name="runbook-runtime-guard",
                incident_id=incident_id,
            )
        )

    @classmethod
    async def collect_snapshot(
        cls,
        *,
        runbook_id: str,
        target: str,
        parameters: Dict[str, Any],
        incident_id: str,
        phase: str,
    ) -> Dict[str, Any]:
        if runbook_id != cls.VM_SERVICE_RUNBOOK:
            return {
                "supported": False,
                "read_success": False,
                "error": "runbook_runtime_guard_not_implemented",
                "context": {"live_evidence": {"evidence": []}},
                "evidence": [],
            }

        service = str(parameters.get("service") or "").strip()
        if not service:
            return {
                "supported": True,
                "read_success": False,
                "error": "service_required",
                "context": {"live_evidence": {"evidence": []}},
                "evidence": [],
            }

        reads: List[tuple[str, Dict[str, Any]]] = [
            ("service_status", {"service": service}),
            ("config_validate", {"service": service}),
        ]
        raw_port = parameters.get("target_port")
        port = None
        if raw_port not in (None, ""):
            try:
                candidate = int(raw_port)
                if 1 <= candidate <= 65535:
                    port = candidate
            except (TypeError, ValueError):
                port = None
        if port is not None:
            reads.extend(
                [
                    ("port_listener_status", {"port": port}),
                    ("tcp_check", {"host": target, "port": port}),
                ]
            )

        evidence: List[Dict[str, Any]] = []
        all_success = True
        errors: List[str] = []
        for action, read_parameters in reads:
            result = await cls._vm_read(
                action=action,
                target=target,
                parameters=read_parameters,
                incident_id=incident_id,
            )
            raw = dict(result.result or {})
            raw.setdefault("diagnostic", action)
            raw.setdefault("target", target)
            raw.setdefault("service", service)
            if port is not None and action in {
                "port_listener_status",
                "tcp_check",
            }:
                raw.setdefault("port", port)
                raw.setdefault("target_port", port)
            if not result.success:
                all_success = False
                error = str(
                    result.error
                    or result.reason
                    or f"{action}_collection_failed"
                )
                errors.append(error)
                raw["collection_success"] = False
                raw["collection_error"] = error
            else:
                raw["collection_success"] = True

            evidence.append(
                {
                    "source": "vm_mcp",
                    "type": "event",
                    "reference": (
                        f"runbook:{phase}:{incident_id}:{action}:"
                        f"{target}:{service}"
                    ),
                    "raw_data": raw,
                }
            )

        return {
            "supported": True,
            "read_success": all_success,
            "error": "; ".join(errors) if errors else None,
            "context": {"live_evidence": {"evidence": evidence}},
            "evidence": evidence,
        }

    @classmethod
    def preflight(
        cls,
        *,
        runbook_id: str,
        tool_name: str,
        action: str,
        target: str,
        parameters: Dict[str, Any],
        incident_id: str,
        evidence: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if runbook_id != cls.VM_SERVICE_RUNBOOK:
            return {
                "safe_to_execute": False,
                "reason": "runbook_runtime_guard_not_implemented",
                "evidence_refs": [],
            }
        return RemediationPlanner.revalidate_execution(
            {
                "tool_name": tool_name,
                "action": action,
                "target": target,
                "parameters": dict(parameters or {}),
                "incident_id": incident_id,
                "runbook_id": runbook_id,
                "rollback": False,
            },
            evidence,
        )

    @staticmethod
    def approval_should_be_revoked(precondition: Dict[str, Any]) -> bool:
        """Return True only when fresh evidence proves the approved intent is stale.

        Transient evidence/telemetry failures remain retryable until TTL; a
        recovered service or changed required recovery action invalidates the
        approved authority itself.
        """
        reason = str(precondition.get("reason") or "").strip()
        return reason in {
            "service_no_longer_unhealthy",
            "service_state_conflict_or_recovered",
            "fresh_service_recovery_action_changed",
        }

    @staticmethod
    async def verify(
        *,
        runbook: Dict[str, Any],
        action: str,
        service: str,
        before_context: Dict[str, Any],
        after_context: Dict[str, Any],
    ) -> VerificationResult:
        verification = dict(runbook.get("verification") or {})
        checks = [
            item
            for item in verification.get("checks", [])
            if isinstance(item, dict)
        ]
        return await VerificationEngine.verify_action(
            action_plan=action,
            service=service,
            before_context=before_context,
            after_context=after_context,
            verification_objectives=checks,
        )
