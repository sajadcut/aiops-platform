from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from apps.runbook_service.registry import RunbookRegistry


class RemediationPlanner:
    """Deterministically bind live operational Evidence to a governed write request.

    The planner never converts free-form LLM/RCA prose into commands. It may only
    emit an execution request when a registered runbook explicitly authorizes the
    tool/action and Live Evidence independently proves the VM target, service and
    unhealthy service state. The Decision/Approval/Capability/Execution boundaries
    remain authoritative after planning.
    """

    VM_SERVICE_RUNBOOK = "vm-service-recovery"
    SIGNAL_SOURCES = {"zabbix", "prometheus", "elasticsearch", "kubernetes"}
    UNHEALTHY_SERVICE_STATES = {
        "inactive", "failed", "dead", "stopped", "down", "not-running", "not_running",
    }

    @classmethod
    def plan(cls, state: Dict[str, Any]) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "status": "not_planned",
            "reason": "no_governed_remediation_match",
            "live_identity_verified": False,
            "execution_request": None,
            "evidence_refs": [],
        }

        evaluation = dict(state.get("evaluation") or {})
        if evaluation.get("approved_for_decision") is not True:
            return {**base, "reason": "evaluation_not_approved"}

        context = dict(state.get("context") or {})
        trigger_signal = context.get("trigger_signal")
        if not isinstance(trigger_signal, dict):
            return {**base, "reason": "automatic_planning_requires_source_trigger"}
        source = str(trigger_signal.get("source") or "").strip().lower()
        if source not in cls.SIGNAL_SOURCES:
            return {**base, "reason": "trigger_source_not_auto_remediation_eligible"}

        policy = cls._load_vm_service_policy()
        if policy is None:
            return {**base, "reason": "vm_service_recovery_runbook_unavailable"}

        evidence = cls._evidence_items(state)
        service_bindings = cls._unhealthy_service_bindings(evidence)
        if not service_bindings:
            return {**base, "reason": "no_live_inactive_service_evidence"}
        if len(service_bindings) != 1:
            return {**base, "reason": "ambiguous_live_service_binding"}

        (target, service), status_refs = next(iter(service_bindings.items()))
        config_ok, config_refs, config_reason = cls._configuration_precondition(
            evidence, target=target, service=service
        )
        if not config_ok:
            return {
                **base,
                "reason": config_reason,
                "target": target,
                "service": service,
                "evidence_refs": cls._dedupe(status_refs + config_refs),
            }

        port, port_refs, port_reason = cls._target_port(evidence, target=target, service=service)
        if port_reason:
            return {
                **base,
                "reason": port_reason,
                "target": target,
                "service": service,
                "evidence_refs": cls._dedupe(status_refs + config_refs + port_refs),
            }

        action = "restart_service"
        tool_name = str((policy.get("execution") or {}).get("tool") or "")
        allowed_actions = {
            str(value).strip()
            for value in (policy.get("execution") or {}).get("allowed_actions", [])
            if str(value).strip()
        }
        step_actions = {
            str(step.get("action") or "").strip()
            for step in policy.get("steps", [])
            if isinstance(step, dict)
        }
        if tool_name != "ssh_vm" or action not in allowed_actions or action not in step_actions:
            return {**base, "reason": "runbook_execution_contract_mismatch"}
        if (policy.get("execution") or {}).get("auto_plan_from_signals") is not True:
            return {**base, "reason": "runbook_automatic_planning_disabled"}

        parameters: Dict[str, Any] = {"service": service}
        if port is not None:
            parameters["target_port"] = port

        request = {
            "tool_name": tool_name,
            "action": action,
            "target": target,
            "parameters": parameters,
            "timeout": int(policy.get("timeout") or 30),
            "agent_name": "remediation_planner",
            "incident_id": state.get("incident_id"),
            "runbook_id": str(policy.get("id") or cls.VM_SERVICE_RUNBOOK),
            "runbook_version": str(policy.get("version") or ""),
            "rollback": False,
        }
        refs = cls._dedupe(status_refs + config_refs + port_refs)
        return {
            "status": "planned",
            "reason": "live_vm_service_inactive_matches_governed_runbook",
            "live_identity_verified": True,
            "source": source,
            "target": target,
            "service": service,
            "target_port": port,
            "runbook_id": request["runbook_id"],
            "runbook_version": request["runbook_version"],
            "evidence_refs": refs,
            "execution_request": request,
        }

    @classmethod
    def _load_vm_service_policy(cls) -> Optional[Dict[str, Any]]:
        try:
            registry = RunbookRegistry()
            runbook = registry.get(cls.VM_SERVICE_RUNBOOK)
            validation = registry.validate(cls.VM_SERVICE_RUNBOOK, {})
        except (KeyError, OSError, TypeError, ValueError):
            return None
        if not validation.get("valid"):
            return None
        return runbook

    @staticmethod
    def _evidence_items(state: Dict[str, Any]) -> List[Dict[str, Any]]:
        context = dict(state.get("context") or {})
        candidates = context.get("evidence")
        if not isinstance(candidates, list):
            live = state.get("live_evidence") or context.get("live_evidence") or {}
            candidates = live.get("evidence", []) if isinstance(live, dict) else []
        return [item for item in candidates if isinstance(item, dict)]

    @classmethod
    def _unhealthy_service_bindings(
        cls, evidence: Iterable[Dict[str, Any]]
    ) -> Dict[Tuple[str, str], List[str]]:
        bindings: Dict[Tuple[str, str], List[str]] = {}
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict) or str(raw.get("diagnostic") or "").strip().lower() != "service_status":
                continue
            target = str(raw.get("target") or "").strip()
            service = str(raw.get("service") or "").strip()
            if not target or not service:
                continue
            state = str(
                raw.get("active_state")
                or raw.get("status")
                or raw.get("state")
                or raw.get("sub_state")
                or ""
            ).strip().lower()
            if state not in cls.UNHEALTHY_SERVICE_STATES:
                continue
            ref = str(item.get("reference") or "").strip()
            bindings.setdefault((target, service), [])
            if ref:
                bindings[(target, service)].append(ref)
        return bindings

    @staticmethod
    def _configuration_precondition(
        evidence: Iterable[Dict[str, Any]], *, target: str, service: str
    ) -> Tuple[bool, List[str], str]:
        matching: List[Tuple[Dict[str, Any], str]] = []
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict) or str(raw.get("diagnostic") or "").strip().lower() != "config_validate":
                continue
            if str(raw.get("target") or "").strip() != target or str(raw.get("service") or "").strip() != service:
                continue
            matching.append((raw, str(item.get("reference") or "").strip()))

        refs = [ref for _, ref in matching if ref]
        if not matching:
            return False, refs, "configuration_validation_evidence_missing"

        for raw, _ in matching:
            if raw.get("supported") is True and raw.get("valid") is not True:
                return False, refs, "service_configuration_invalid"

        if any(raw.get("valid") is True or raw.get("supported") is False for raw, _ in matching):
            return True, refs, "configuration_precondition_satisfied"
        return False, refs, "configuration_validation_inconclusive"

    @staticmethod
    def _target_port(
        evidence: Iterable[Dict[str, Any]], *, target: str, service: str
    ) -> Tuple[Optional[int], List[str], Optional[str]]:
        ports: set[int] = set()
        refs: List[str] = []
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict):
                continue
            diagnostic = str(raw.get("diagnostic") or "").strip().lower()
            if diagnostic not in {"port_listener_status", "tcp_check"}:
                continue
            if str(raw.get("target") or "").strip() != target:
                continue
            raw_service = str(raw.get("service") or "").strip()
            if raw_service and raw_service != service:
                continue
            raw_port = raw.get("target_port") or raw.get("port")
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)
                ref = str(item.get("reference") or "").strip()
                if ref:
                    refs.append(ref)
        if len(ports) > 1:
            return None, refs, "ambiguous_live_target_port"
        return (next(iter(ports)) if ports else None), refs, None

    @staticmethod
    def _dedupe(values: Iterable[str]) -> List[str]:
        return list(dict.fromkeys(str(value) for value in values if str(value).strip()))
